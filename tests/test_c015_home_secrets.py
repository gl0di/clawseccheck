"""C015 — secrets-at-rest scan of the OpenClaw home."""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_secrets_at_rest_home
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home: Path, cfg: dict | None = None) -> Context:
    ctx = Context(home=home)
    ctx.config = cfg or {}
    return ctx


def _runtime_secret() -> str:
    return "ghp" + "_" + "A" * 36


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
