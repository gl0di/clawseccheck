"""C015 — secrets-at-rest scan of the OpenClaw home."""
from __future__ import annotations

import shutil
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import _C015_MAX_SCAN_FILES, check_secrets_at_rest_home
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home: Path, cfg: dict | None = None) -> Context:
    ctx = Context(home=home)
    ctx.config = cfg or {}
    return ctx


def _runtime_secret() -> str:
    return "ghp" + "_" + "A" * 36


def _seed_fixture_with_runtime_secret(src_dir: Path, dest_dir: Path, secret: str) -> None:
    """Copy a fixture tree to *dest_dir*, substituting the ``__RUNTIME_SECRET__``
    placeholder in every text file for a secret assembled only at test time (ZKDS:
    no contiguous secret-shaped literal ever lives on disk in the repo)."""
    shutil.copytree(src_dir, dest_dir, dirs_exist_ok=True)
    for path in dest_dir.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if "__RUNTIME_SECRET__" in text:
            mode = path.stat().st_mode
            path.write_text(text.replace("__RUNTIME_SECRET__", secret), encoding="utf-8")
            path.chmod(mode)


def test_c015_unknown_when_no_candidate_files(tmp_path):
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_c015_warns_without_echoing_secret_value(tmp_path):
    secret = _runtime_secret()
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / ".env").write_text("API_TOKEN=" + secret + "\n", encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert secret not in f.detail
    assert all(secret not in item for item in f.evidence)
    assert any(".env: secret-like value detected" in item for item in f.evidence)


def test_c015_passes_clean_fixture():
    f = check_secrets_at_rest_home(collect(FIXTURES / "clean_c015_home_secrets"))
    assert f.status == PASS


def test_c015_ignores_codex_plugin_doc_cache_placeholders(tmp_path):
    """B-124: vendored plugin doc-cache markdown with placeholder secret-shaped
    text must not trigger C015 — it is third-party documentation, not a real
    secret created by the user or agent."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    doc_cache = (
        tmp_path / "agents" / "main" / "agent" / "codex-home"
        / ".tmp" / "plugins" / "plugins" / "base44"
    )
    doc_cache.mkdir(parents=True)
    (doc_cache / "secrets-set.md").write_text(
        "API_KEY=abc123 DB_PASSWORD=secret\n", encoding="utf-8"
    )
    other_plugin = (
        tmp_path / "agents" / "main" / "agent" / "codex-home"
        / ".tmp" / "plugins" / "plugins" / "boltz-api-cli"
    )
    other_plugin.mkdir(parents=True)
    (other_plugin / "auth.md").write_text('password:"securePassword123"\n', encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == PASS


def test_c015_still_flags_real_secret_outside_doc_cache(tmp_path):
    """A real secret in a normal, user-authored config file must still trigger
    C015 — the doc-cache exclusion must not weaken genuine detection."""
    secret = _runtime_secret()
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    doc_cache = (
        tmp_path / "agents" / "main" / "agent" / "codex-home"
        / ".tmp" / "plugins" / "plugins" / "base44"
    )
    doc_cache.mkdir(parents=True)
    (doc_cache / "secrets-set.md").write_text(
        "API_KEY=abc123 DB_PASSWORD=secret\n", encoding="utf-8"
    )
    (tmp_path / "workspace-home").mkdir()
    (tmp_path / "workspace-home" / ".env").write_text(
        "TOKEN=" + secret + "\n", encoding="utf-8"
    )
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert any(".env: secret-like value detected" in item for item in f.evidence)


def test_c015_bad_fixture_can_be_seeded_at_runtime(tmp_path):
    src = FIXTURES / "bad_c015_home_secrets"
    (tmp_path / "workspace-home").mkdir(parents=True)
    (tmp_path / "openclaw.json").write_text(
        (src / "openclaw.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    secret = _runtime_secret()
    (tmp_path / "workspace-home" / "notes.env").write_text(
        "TOKEN=" + secret + "\n", encoding="utf-8"
    )
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN



def test_c015_present_in_audit_results(tmp_path):
    secret = _runtime_secret()
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "workspace-home").mkdir()
    (tmp_path / "workspace-home" / ".env").write_text(
        "SECRET=" + secret + "\n", encoding="utf-8"
    )
    _, findings, _ = audit(tmp_path, include_native=False)
    by_id = {f.id: f for f in findings}
    assert by_id["C015"].status == WARN


# ---------------------------------------------------------------------------
# B-133: identity/ device keypair + devices/ paired-operator tokens
# ---------------------------------------------------------------------------

def test_c015_flags_identity_device_private_key(tmp_path):
    """A real identity/device.json private key must now be scanned and flagged —
    before B-133 this file was silently skipped."""
    secret = _runtime_secret()
    _seed_fixture_with_runtime_secret(
        FIXTURES / "bad_c015_identity_devices", tmp_path, secret
    )
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert secret not in f.detail
    assert all(secret not in item for item in f.evidence)
    assert any("identity/device.json" in item for item in f.evidence)


def test_c015_flags_devices_paired_operator_token(tmp_path):
    """A devices/paired.json entry carrying an operator.admin scope + a live
    accessToken must be flagged — before B-133 this file was silently skipped."""
    secret = _runtime_secret()
    _seed_fixture_with_runtime_secret(
        FIXTURES / "bad_c015_identity_devices", tmp_path, secret
    )
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert secret not in f.detail
    assert all(secret not in item for item in f.evidence)
    assert any("devices/paired.json" in item for item in f.evidence)


def test_c015_passes_clean_identity_devices_fixture():
    """identity/device.json without a private key and devices/paired.json with a
    scope grant but no live token value must stay clean — widening the candidate
    set to identity/ and devices/ must not introduce false positives."""
    f = check_secrets_at_rest_home(collect(FIXTURES / "clean_c015_identity_devices"))
    assert f.status == PASS


# ---------------------------------------------------------------------------
# B-131: config backup siblings (openclaw.json.bak / .last-good / .pre-update)
# ---------------------------------------------------------------------------

def test_c015_flags_openclaw_json_bak_backup(tmp_path):
    """openclaw.json.bak duplicating a live gateway.auth.token must now be
    scanned and flagged — before B-131 only the exact 'openclaw.json' name was
    admitted as a candidate."""
    secret = _runtime_secret()
    _seed_fixture_with_runtime_secret(
        FIXTURES / "bad_c015_config_backup", tmp_path, secret
    )
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert secret not in f.detail
    assert all(secret not in item for item in f.evidence)
    assert any("openclaw.json.bak" in item for item in f.evidence)


def test_c015_flags_openclaw_json_last_good_backup(tmp_path):
    """openclaw.json.last-good and openclaw.json.pre-update are admitted the
    same way as .bak — a name-prefix check, not an exhaustive suffix enum."""
    secret = _runtime_secret()
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "openclaw.json.last-good").write_text(
        '{"gateway":{"auth":{"token":"' + secret + '"}}}\n', encoding="utf-8"
    )
    (tmp_path / "openclaw.json.pre-update").write_text("{}\n", encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert any("openclaw.json.last-good" in item for item in f.evidence)


def test_c015_still_scans_normal_locations_after_widening(tmp_path):
    """Regression: widening the candidate set for B-131/B-133 must not disturb
    detection of a real secret in a normal, already-covered location."""
    secret = _runtime_secret()
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / ".env").write_text("API_TOKEN=" + secret + "\n", encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert any(".env: secret-like value detected" in item for item in f.evidence)


# ---------------------------------------------------------------------------
# C-226: SecretRef indirection (${NAME} / $NAME / secretref-env: / __env__: /
# structured {source, provider, id}) is a SAFER OpenClaw 2026.7.1 config-value
# shape and must not be misread as an exposed plaintext secret by C015 either.
# ---------------------------------------------------------------------------

def test_c015_passes_config_with_every_secretref_indirection_shape(tmp_path):
    """Clean: an openclaw.json whose secret-shaped fields are ALL SecretRef
    indirection (env shorthand, both legacy markers, and the structured object
    form) must stay PASS — none of these is a plaintext secret."""
    cfg_text = (
        "{\n"
        '  "gateway": {"auth": {"token": "${OPENAI_KEY}"}},\n'
        '  "providers": {"openai": {"apiKey": "$OPENAI_KEY"}},\n'
        '  "hooks": {"secretToken": "secretref-env:HOOKS_TOKEN"},\n'
        '  "legacy": {"apiKey": "__env__:LEGACY_TOKEN"},\n'
        '  "someService": {\n'
        '    "apiKey": {"source": "env", "provider": "default", "id": "OPENAI_KEY"}\n'
        "  }\n"
        "}\n"
    )
    (tmp_path / "openclaw.json").write_text(cfg_text, encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == PASS


def test_c015_adversarial_decoy_reference_does_not_mask_real_secret_elsewhere(tmp_path):
    """Case 1: a decoy ${NAME} reference in one field and a real contiguous secret
    in ANOTHER field of the SAME file — the real secret must still WARN (the
    decoy match must not be the only one .search()/.finditer() ever inspects)."""
    secret = _runtime_secret()
    cfg_text = (
        "{\n"
        '  "gateway": {"auth": {"token": "${OPENAI_KEY}"}},\n'
        '  "hooks": {"token": "' + secret + '"}\n'
        "}\n"
    )
    (tmp_path / "openclaw.json").write_text(cfg_text, encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert any("openclaw.json" in item for item in f.evidence)


def test_c015_adversarial_appended_secret_after_reference_still_warns(tmp_path):
    """Case 2: ${NAME} immediately followed by appended real secret material in the
    SAME value is NOT a pure reference — must still WARN."""
    secret = _runtime_secret()
    cfg_text = '{"gateway": {"auth": {"token": "${OPENAI_KEY}' + secret + '"}}}\n'
    (tmp_path / "openclaw.json").write_text(cfg_text, encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN


def test_c015_adversarial_secretref_env_prefix_with_inline_blob_still_warns(tmp_path):
    """Case 3: 'secretref-env:' prefix followed by an inline plaintext blob (not a
    bare uppercase env-var-name token — the only shape OpenClaw itself treats as a
    real reference) must still WARN."""
    cfg_text = (
        '{"gateway": {"auth": '
        '{"token": "secretref-env:actually-a-plaintext-blob-appended-here"}}}\n'
    )
    (tmp_path / "openclaw.json").write_text(cfg_text, encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN


# ---------------------------------------------------------------------------
# B-244: the walk-cap truncation family — a bulk/excluded subtree that sorts before
# the real content must not silently starve the scan, and if the cap IS genuinely hit,
# the verdict must disclose it rather than reading as a complete scan.
# ---------------------------------------------------------------------------

def _make_bulk_files(dirpath: Path, count: int, ext: str = ".md", body: str = "nothing here\n") -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (dirpath / f"file{i:05d}{ext}").write_text(body, encoding="utf-8")


def test_c015_prunes_codex_cache_before_budget_so_later_secret_is_still_found(tmp_path):
    """B-244 repro: a codex-plugin-doc-cache subtree alone big enough to blow the
    _C015_MAX_SCAN_FILES walk cap (sorts before 'workspace' under 'agents') must NOT
    starve a real secret living in workspace/ — the cache is now excluded from the walk
    itself, before it can consume any of the budget."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    doc_cache = (
        tmp_path / "agents" / "main" / "agent" / "codex-home"
        / ".tmp" / "plugins" / "plugins" / "base44"
    )
    _make_bulk_files(doc_cache, _C015_MAX_SCAN_FILES + 100, body="API_KEY=abc123 not-a-real-secret\n")

    secret = _runtime_secret()
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "PASSWORDS.md").write_text(
        "- Password: " + secret + "\n", encoding="utf-8"
    )

    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert any("workspace/PASSWORDS.md" in item for item in f.evidence)
    # The whole excluded cache never touched the budget, so this scan never capped.
    assert "walk cap" not in f.detail


def test_c015_flags_truncation_caveat_when_generic_bulk_hits_cap_with_no_secret_found(tmp_path):
    """A large, NON-excluded early-alphabet subtree that genuinely exhausts the walk
    cap before a later directory is reached must downgrade the clean verdict from a
    confident PASS to an UNKNOWN that discloses the coverage gap (GR#4 / B-228
    family) — never a clean 'scanned the home' headline over a partial scan."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _make_bulk_files(tmp_path / "aaa_bulk", _C015_MAX_SCAN_FILES + 100)
    (tmp_path / "workspace").mkdir()
    (tmp_path / "workspace" / "notes.md").write_text("just notes, nothing secret\n", encoding="utf-8")

    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == UNKNOWN
    assert "coverage is incomplete" in f.detail
    assert f"{_C015_MAX_SCAN_FILES}-file walk cap" in f.detail


def test_c015_capped_scan_still_warns_on_secret_found_before_the_cap(tmp_path):
    """If a real secret is found in the portion of the home scanned before the cap
    was hit, the WARN must still fire (a truncated scan is not a reason to suppress a
    positive hit) — but the detail must still disclose that the scan was capped, so a
    reader knows there may be MORE secrets in the unreached remainder."""
    secret = _runtime_secret()
    (tmp_path / "aaa_secret.env").write_text("TOKEN=" + secret + "\n", encoding="utf-8")
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    _make_bulk_files(tmp_path / "bbb_bulk", _C015_MAX_SCAN_FILES + 100)

    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == WARN
    assert any("aaa_secret.env" in item for item in f.evidence)
    assert "walk cap" in f.detail


def test_c015_small_home_has_no_spurious_truncation_caveat(tmp_path):
    """Regression: a home well under the scan cap must read exactly as before — no
    caveat text leaking into a genuinely complete scan."""
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    f = check_secrets_at_rest_home(_ctx(tmp_path))
    assert f.status == PASS
    assert "walk cap" not in f.detail
    assert "coverage is incomplete" not in f.detail
