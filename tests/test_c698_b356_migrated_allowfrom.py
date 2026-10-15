"""B356 (CLAWSECCHECK-C-698): a legacy allow-sender store that Doctor has set aside is clean.

OpenClaw 2026.10.2's Doctor renames the legacy ``credentials/<channel>-allowFrom.json`` of a
removed channel account to ``...-allowFrom.json.migrated`` (a second copy becomes
``.migrated.2``, the vendor's own archive scheme in ``state-migrations.doctor``) instead of
stopping on it. B356's marker is the exact ``-allowFrom.json`` suffix, so a renamed file is
not matched and the advice "run ``openclaw doctor --fix`` and confirm the file(s) are gone"
became achievable for that shape. Nothing pinned that; this file does, in both directions:
the set-aside copies read as clean, and the same channel's unsuffixed file still warns.

Filename presence only - no file content is read. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_legacy_state_migration_pending
from clawseccheck.collector import Context


def _home(tmp_path, *names):
    cred = tmp_path / "credentials"
    cred.mkdir()
    for name in names:
        (cred / name).write_text("[]")
    return Context(home=tmp_path)


def test_set_aside_allowfrom_copies_are_clean(tmp_path):
    ctx = _home(
        tmp_path,
        "telegram-gone-allowFrom.json.migrated",
        "telegram-gone-allowFrom.json.migrated.2",
    )
    f = check_legacy_state_migration_pending(ctx)
    assert f.status == PASS
    assert not f.evidence


def test_the_unsuffixed_twin_still_warns_and_names_the_channel(tmp_path):
    ctx = _home(tmp_path, "telegram-gone-allowFrom.json")
    f = check_legacy_state_migration_pending(ctx)
    assert f.status == WARN
    assert f.evidence == [
        "credentials/telegram-gone-allowFrom.json (legacy per-channel allow-sender store)"
    ]


def test_a_set_aside_copy_beside_an_unsuffixed_file_names_only_the_unsuffixed_one(tmp_path):
    ctx = _home(
        tmp_path,
        "telegram-gone-allowFrom.json.migrated",
        "telegram-gone-allowFrom.json.migrated.2",
        "discord-allowFrom.json",
    )
    f = check_legacy_state_migration_pending(ctx)
    assert f.status == WARN
    assert f.evidence == [
        "credentials/discord-allowFrom.json (legacy per-channel allow-sender store)"
    ]
    assert not any(".migrated" in e for e in f.evidence)
    assert ".migrated" not in f.detail
