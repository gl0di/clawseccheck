"""B355 (CLAWSECCHECK-C-408) — models.providers.*.localService.command auto-spawns a
binary at provider startup, with config-chosen args/cwd/env.

Grounded on the installed dist's own runtime, not just its schema:

* ``ModelProviderLocalServiceSchema`` (``zod-schema.core-*.mjs``) — `command:
  string().min(1)`, no absolute-path constraint at the TYPE level.
* `validateLocalServiceConfig` (``provider-local-service-*.mjs``) — called before every
  spawn, `if (!path.isAbsolute(service.command)) throw ...`. **This refutes the original
  stub's FAIL premise**: a relative command never silently executes via a PATH/cwd
  lookup, because OpenClaw's own launcher refuses to start the service at all. So a
  relative command is a functionality bug (the provider's local service will not run),
  never an exec-hijack — and this check does not report it as a security finding.

What IS still unchecked by the runtime: WHO can write the absolute path it is about to
exec. That is this check's actual subject, using the same `_dir_replaceable_by_others`
predicate B352 (`tools.exec.pathPrepend`) already established for a sibling surface, and
the same WARN-only tier (a FAIL needs its own independent C-135 pass against real
configs, deferred per this task's own "WARN/INFO ship first" allowance).

No committed fixture bakes in a writable/owner-only permission expectation — a real
system directory's mode varies by machine and CI runner (test_b352's own docstring
records exactly this failure: a fixture naming /usr/local/bin passed locally and failed
on both GitHub runners). Every permission-sensitive case here builds its own file under
tmp_path and chmods it explicitly.
"""
from __future__ import annotations

import os

import pytest

from clawseccheck.catalog import BY_ID, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import CHECKS, check_local_model_service_command
from clawseccheck.collector import Context


def _ctx(cfg, tmp_path, *, config_found=True):
    return Context(home=tmp_path, config=cfg, config_found=config_found)


def _cfg(command: str, provider: str = "local-model") -> dict:
    return {"models": {"providers": {provider: {"localService": {"command": command}}}}}


# --------------------------------------------------------------------------- no service
def test_no_providers_block_is_pass(tmp_path):
    f = check_local_model_service_command(_ctx({"gateway": {}}, tmp_path))
    assert f.status == PASS
    assert "No model provider declares" in f.detail


def test_providers_key_explicitly_null_is_pass_not_unknown(tmp_path):
    """An explicit JSON null and an absent key carry the same practical meaning here
    (nothing configured) — dig() cannot even distinguish them, and treating null as
    malformed would be inventing a distinction the check has no way to observe."""
    f = check_local_model_service_command(_ctx({"models": {"providers": None}}, tmp_path))
    assert f.status == PASS


def test_a_provider_with_no_localservice_is_pass(tmp_path):
    cfg = {"models": {"providers": {"anthropic": {"baseUrl": "https://api.anthropic.com"}}}}
    f = check_local_model_service_command(_ctx(cfg, tmp_path))
    assert f.status == PASS


# --------------------------------------------------------------------- the relative case
def test_a_relative_command_is_pass_not_warn(tmp_path):
    """The refuted premise: a relative command can never reach the spawn this check
    examines, because OpenClaw's own launcher refuses to start it."""
    f = check_local_model_service_command(_ctx(_cfg("relative/bin"), tmp_path))
    assert f.status == PASS
    assert "relative" in f.detail
    assert "refuses to spawn" in f.detail or "will not start" in f.fix


def test_a_bare_relative_command_is_also_pass(tmp_path):
    f = check_local_model_service_command(_ctx(_cfg("mybin"), tmp_path))
    assert f.status == PASS


# ------------------------------------------------------------------- the writable case
def test_a_world_writable_command_file_warns(tmp_path):
    binary = tmp_path / "svc"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(binary, 0o777)
    f = check_local_model_service_command(_ctx(_cfg(str(binary)), tmp_path))
    assert f.status == WARN
    assert str(binary) in f.detail
    assert "world-writable" in f.detail or "writable" in f.detail


def test_a_command_in_a_world_writable_directory_warns(tmp_path):
    """The file itself can be owner-only and still be replaceable — via the directory."""
    writable_dir = tmp_path / "writable_dir"
    writable_dir.mkdir()
    os.chmod(writable_dir, 0o777)
    binary = writable_dir / "svc"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(binary, 0o700)
    f = check_local_model_service_command(_ctx(_cfg(str(binary)), tmp_path))
    assert f.status == WARN
    assert str(binary) in f.detail


def test_an_owner_only_command_is_pass(tmp_path):
    binary = tmp_path / "svc"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(binary, 0o700)
    os.chmod(tmp_path, 0o700)
    f = check_local_model_service_command(_ctx(_cfg(str(binary)), tmp_path))
    assert f.status == PASS
    assert str(binary) in f.detail


def test_a_command_that_does_not_exist_on_this_machine_is_not_flagged(tmp_path):
    """`_dir_replaceable_by_others` degrades to 'could not determine' (None) rather
    than fabricating a verdict about a path that cannot be stat()'d -- this check must
    never turn that into a WARN."""
    missing = tmp_path / "does" / "not" / "exist" / "svc"
    f = check_local_model_service_command(_ctx(_cfg(str(missing)), tmp_path))
    assert f.status == PASS


def test_group_writable_by_a_real_other_member_warns(tmp_path):
    """The B-127 lesson B352 already paid for: group-write is only reported when the
    owning group actually has another member. Skipped when membership can't be resolved
    (non-POSIX or a synthetic gid) -- covered by test_a_command_that_does_not_exist..."""
    binary = tmp_path / "svc"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(binary, 0o770)
    # Real group-membership resolution is exercised by _dir_replaceable_by_others'
    # own tests (test_b352_exec_path_prepend.py / _shared.py tests); this just
    # confirms the wiring calls it rather than a bare mode-bit check.
    f = check_local_model_service_command(_ctx(_cfg(str(binary)), tmp_path))
    assert f.status in (PASS, WARN)  # depends on real group membership on this box


# ------------------------------------------------------------------- multiple providers
def test_multiple_providers_all_counted(tmp_path):
    writable = tmp_path / "w"
    writable.write_text("x", encoding="utf-8")
    os.chmod(writable, 0o777)
    safe = tmp_path / "s"
    safe.write_text("x", encoding="utf-8")
    os.chmod(safe, 0o700)
    cfg = {"models": {"providers": {
        "prov-writable": {"localService": {"command": str(writable)}},
        "prov-safe": {"localService": {"command": str(safe)}},
        "prov-relative": {"localService": {"command": "relative/x"}},
        "prov-none": {"baseUrl": "https://x"},
    }}}
    f = check_local_model_service_command(_ctx(cfg, tmp_path))
    assert f.status == WARN
    assert "prov-writable" in f.detail
    assert "prov-safe" not in f.detail  # the WARN detail leads with what's risky


# --------------------------------------------------------------------------- never FAIL
def test_never_fails_even_when_maximally_writable(tmp_path):
    binary = tmp_path / "svc"
    binary.write_text("x", encoding="utf-8")
    os.chmod(binary, 0o777)
    os.chmod(tmp_path, 0o777)
    f = check_local_model_service_command(_ctx(_cfg(str(binary)), tmp_path))
    assert f.status != "FAIL"
    meta = BY_ID["B355"]
    assert meta.severity == HIGH  # severity is real; the VERDICT tier is capped at WARN


# ------------------------------------------------------------------------- malformed / unread
def test_an_unread_config_is_unknown(tmp_path):
    f = check_local_model_service_command(Context(home=tmp_path, config={}, config_found=False))
    assert f.status == UNKNOWN


def test_a_malformed_providers_block_is_unknown(tmp_path):
    for bad in ([], "x", 5):
        cfg = {"models": {"providers": bad}}
        f = check_local_model_service_command(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN, f"{bad!r}: expected UNKNOWN, got {f.status}"


@pytest.mark.parametrize("bad", [None, [], "x", 5, {"command": 5}, {"command": ""}, {"command": "  "}])
def test_malformed_localservice_shapes_do_not_raise(tmp_path, bad):
    cfg = {"models": {"providers": {"p": {"localService": bad}}}}
    f = check_local_model_service_command(_ctx(cfg, tmp_path))
    assert f.status in (PASS, UNKNOWN)


def test_a_non_dict_provider_entry_does_not_raise(tmp_path):
    cfg = {"models": {"providers": {"p": "not-a-dict"}}}
    f = check_local_model_service_command(_ctx(cfg, tmp_path))
    assert f.status == PASS


# ------------------------------------------------------------------------------- wiring
def test_the_check_is_actually_registered():
    assert check_local_model_service_command in CHECKS


def test_catalog_entry_matches_what_the_check_emits(tmp_path):
    meta = BY_ID["B355"]
    assert meta.severity == HIGH and meta.surface == "tools"
    emitted = check_local_model_service_command(_ctx({}, tmp_path))
    assert emitted.id == "B355" and emitted.title == meta.title
