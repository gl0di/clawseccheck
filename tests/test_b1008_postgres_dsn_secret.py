"""OpenClaw 2026.10.10's ``database.postgres.connection`` is a vendor ``SecretInput``
(``SecretInputSchema``, registered ``sensitive``, resolved by
``resolveCanonicalConfiguredSecretInputString`` and passed to node-pg as
``new Client({ connectionString })``). Before this rule a plaintext DSN with a password was read
as clean by B1 and C015, and the C-688 drift guard named the path as a gap.

Only a password IN the string counts - a DSN without one (peer / trust auth, pgpass,
PGPASSWORD) is ordinary configuration. The forms are the ones node-pg's own parser
(pg-connection-string 2.14.1, executed against the installed dist on 2026-11-04) reads: URL
userinfo and the ``?password=`` query parameter, for ``postgres://``, ``postgresql://`` and
``socket://``, plus ``sslpassword`` (the client-key passphrase) the same two ways. The libpq keyword form (``password=...``) is not parsed by node-pg, but it still
puts the credential in the file, so it counts too. So does an unparseable URL with a password in
its userinfo.

Secret-shaped values are assembled at runtime; the two committed fixtures hold only references.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import (
    _dsn_inline_password,
    _secret_paths,
    _vendor_slot_covers,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
PATH = "database.postgres.connection"


def _pw() -> str:
    raw = base64.b64encode(hashlib.sha256(b"b1008").digest()).decode()
    return "".join(c for c in raw if c.isalnum())[:20]


def _cfg(connection) -> dict:
    return {"database": {"engine": "postgres", "postgres": {"connection": connection}}}


def _bad_dsns() -> list:
    pw = _pw()
    return [
        "postgres://openclaw:" + pw + "@db.internal.example:5432/openclaw",
        "postgresql://openclaw@db.internal.example/openclaw?sslmode=require&password=" + pw,
        "socket://openclaw:" + pw + "@/var/run/postgresql?db=openclaw",
        "host=db.internal.example user=openclaw password=" + pw + " dbname=openclaw",
        "host=db.internal.example password='" + pw + " x'",
        "postgres://openclaw:" + pw + "@[::1",  # unparseable: still a password in the file
        "postgres://openclaw:${PG_PASS:-" + pw + "}@db/openclaw",  # literal fallback
        "postgres://openclaw@db/openclaw?sslmode=verify-full&sslpassword=" + pw,
        "host=db sslkey=/etc/oc/client.key sslpassword=" + pw,
        "postgres://openclaw@db/openclaw?password=%24%7B" + pw + "%7D",  # literal to node-pg
        "host=db password=" + pw + " options='-c search_path=x://y'",  # `://` in a value
        "postgres://openclaw@[::1/openclaw?password=" + pw,  # unparseable, query password
        "postgres://openclaw@db/openclaw?pass%77ord=" + pw,  # node-pg decodes the key
        "postgres://openclaw@db/openclaw?ssl%70assword=" + pw,
    ]


_CLEAN_DSNS = [
    "${OPENCLAW_PG_DSN}",
    "postgres://openclaw:${OPENCLAW_PG_PASSWORD}@db.internal.example/openclaw",
    "postgres://openclaw@db.internal.example/openclaw?password=${OPENCLAW_PG_PASSWORD}",
    "postgres://openclaw:${OPENCLAW_PG_PASSWORD:-}@db/openclaw",
    "postgres://openclaw@localhost/openclaw",
    "postgres://db.internal.example/openclaw?sslmode=require",
    "postgres://openclaw:@localhost/openclaw",
    "/var/run/postgresql openclaw",
    "host=/var/run/postgresql dbname=openclaw",
    "host=db passfile=/etc/openclaw/pgpass",
    "password=${OPENCLAW_PG_PASSWORD}",
    "secretref-env:OPENCLAW_PG_DSN",
    "host=db options='-c password=x' dbname=openclaw",  # inside a quoted value, not a pair
    "host=db application_name='a password=b'",
    "postgres://openclaw@db/openclaw?sslpassword=${OPENCLAW_PG_KEY_PASS}",
    "postgres://openclaw@db/openclaw?PASSWORD=x",  # node-pg reads the lowercase key only
]
_REF = {"source": "env", "provider": "default", "id": "OPENCLAW_PG_DSN"}


# --------------------------------------------------------------------- the slot is covered

def test_the_vendor_path_is_covered_by_a_path_rule():
    assert _vendor_slot_covers(PATH) == "path"
    assert _vendor_slot_covers("database.postgres.schemaPrefix") is None
    assert _vendor_slot_covers("other.postgres.connection") is None


# ------------------------------------------------------------------------- helper level

@pytest.mark.parametrize("index", range(14))
def test_a_dsn_with_a_literal_password_is_reported(index):
    dsn = _bad_dsns()[index]
    assert _dsn_inline_password(dsn) is not None, dsn
    assert _secret_paths(_cfg(dsn)) == [PATH]


@pytest.mark.parametrize("dsn", _CLEAN_DSNS)
def test_a_dsn_without_a_literal_password_is_clean(dsn):
    assert _dsn_inline_password(dsn) is None, dsn
    assert _secret_paths(_cfg(dsn)) == []


def test_a_secretref_object_is_clean():
    assert _secret_paths(_cfg(_REF)) == []


def test_the_rule_is_bound_to_the_vendor_path_only():
    """The same DSN under an unrelated key is not a vendor-sensitive slot."""
    dsn = _bad_dsns()[0]
    assert _secret_paths({"database": {"postgres": {"replicaUrl": dsn}}}) == []
    assert _secret_paths({"plugins": {"x": {"connection": dsn}}}) == []


def test_short_passwords_count_at_any_length():
    assert _secret_paths(_cfg("postgres://u:p@h/db")) == [PATH]


# ------------------------------------------------------------------------- end to end

def _home(tmp_path: Path, cfg: dict, mode: int) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    p = home / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(mode)
    return home


def _status(home: Path) -> tuple:
    _, findings, _ = audit(home)
    by = {f.id: f for f in findings}
    return by["B1"], by["C015"]


@pytest.mark.parametrize("index", [0, 1, 3])
def test_bad_b1_fails_a_readable_config_and_c015_warns(tmp_path, index):
    b1, c015 = _status(_home(tmp_path, _cfg(_bad_dsns()[index]), 0o644))
    assert b1.status == FAIL, b1.detail
    assert c015.status == WARN, c015.detail
    assert _pw() not in json.dumps([b1.detail, b1.evidence, b1.fix, c015.detail, c015.evidence])


def test_bad_b1_passes_with_the_tight_perms_note_when_the_config_is_private(tmp_path):
    b1, c015 = _status(_home(tmp_path, _cfg(_bad_dsns()[0]), 0o600))
    assert b1.status == PASS and "file perms are tight" in b1.detail
    assert c015.status == WARN


@pytest.mark.parametrize(
    "fixture", ["clean_b1_postgres_dsn_secretref", "clean_b1_postgres_dsn_env_password"]
)
def test_clean_fixtures_stay_pass_even_when_readable(tmp_path, fixture):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    shutil.copy(FIXTURES / fixture / "openclaw.json", home / "openclaw.json")
    (home / "openclaw.json").chmod(0o644)
    b1, c015 = _status(home)
    assert b1.status == PASS and "No exposed plaintext secrets." in b1.detail, b1.detail
    assert c015.status == PASS, c015.detail


def test_undecidable_shapes_never_invent_a_secret(tmp_path):
    """No UNKNOWN branch exists for this slot (B1's UNKNOWN is the `:-` build gate on two
    named fields). The shapes we cannot read as a literal - a non-string, an empty value, a
    store-backed SecretRef the vendor itself rejects - say nothing about a password in the
    file, so they stay PASS rather than turning into a guessed FAIL."""
    for value in (None, 5432, "", ["postgres://u:p@h"], {"source": "store", "id": "pg"}):
        assert _secret_paths(_cfg(value)) == [], value
    b1, c015 = _status(_home(tmp_path, _cfg({"source": "store", "id": "pg"}), 0o644))
    assert b1.status == PASS and c015.status == PASS
