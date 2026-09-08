"""The `openclaw_install` dimension — the installed OpenClaw package as an identity marker.

F-174. `openclawdist.py` is the reader; this is the comparison. Three digests move
independently — the manifest, the lock file, and the content digest over the executable
surface — and only the last one catches a swapped build under an untouched manifest, which
is the actual npm supply-chain attack.
"""

from __future__ import annotations
from ..openclawdist import compare_versions as _version_order  # noqa: F401
from ._shared import NOTE_INSPECTION_CAPPED, NOTE_UNDETERMINED  # noqa: F401


def _diff_openclaw_install(_c_inst, _p_inst, alerts, curr, note, prev) -> None:
    """C-433: the diff arm for the installed OpenClaw package.

    The statement is moved **verbatim, condition included**. The previous batch rebuilt an
    `if compare_config and _pair is not None:` as `if pair is None: return`, kept one clause
    and dropped the blind-run interlock, and reintroduced a B-269 fabrication. Moving the
    whole `if` removes that class of error entirely.

    Parameter names keep their original underscore-prefixed spelling for the same reason:
    a rename is an edit, and the contract for this move is that the body is unchanged.
    """
    if _p_inst is None:
        if "openclaw_install" not in curr and "openclaw_install" in prev:
            note(NOTE_UNDETERMINED,
                 "Your OpenClaw installation was not compared: this run could not find it. "
                 "That is normal for a scheduled run, whose search path is narrower than "
                 "yours.")
    else:
        _p_ver, _c_ver = _p_inst.get("version", ""), _c_inst.get("version", "")
        if _p_ver and _c_ver and _p_ver != _c_ver:
            # Direction only when it is defensible — see openclawdist.compare_versions for
            # why a wrong "rolled back" is worse than a bare "changed".
            if _version_order(_p_ver, _c_ver) == "down":
                alerts.append((
                    "HIGH",
                    f"Your OpenClaw installation went BACKWARDS, from {_p_ver} to {_c_ver}. "
                    f"A downgrade re-opens whatever the newer build had fixed, and it is "
                    f"not something a routine update does. Confirm you did this."))
            else:
                alerts.append((
                    "INFO",
                    f"Your OpenClaw installation changed from {_p_ver} to {_c_ver}."))
        elif _p_ver and _c_ver and _p_ver == _c_ver \
                and _p_inst.get("code_sha256") and _c_inst.get("code_sha256") \
                and _p_inst["code_sha256"] != _c_inst["code_sha256"] \
                and not _c_inst.get("code_capped") and not _p_inst.get("code_capped"):
            # The attack the version number cannot show: same version, different build.
            #
            # Gated on both versions being RECORDED and EQUAL, not merely on the version
            # branch above not having fired. The `elif` alone was reached when one side's
            # version was never recorded at all (a manifest with no `version` string), and
            # the sentence then asserted the version "stayed at" a value the other side did
            # not have — claiming a same-version swap out of a missing field.
            alerts.append((
                "HIGH",
                f"Your OpenClaw program files changed while the version number stayed at "
                f"{_c_ver}. A normal update moves both. Re-install OpenClaw from a source "
                f"you trust if you did not do this deliberately."))
        elif (_p_ver and _c_ver and _p_ver == _c_ver
                and not _p_inst.get("code_capped") and not _c_inst.get("code_capped")
                and _p_inst.get("code_sha256") and _c_inst.get("code_sha256")
                and _p_inst["code_sha256"] == _c_inst["code_sha256"]
                and _p_inst.get("lock_sha256") and _c_inst.get("lock_sha256")
                and _p_inst["lock_sha256"] != _c_inst["lock_sha256"]):
            # Every clause of the sentence has to be EVIDENCED, not merely un-contradicted.
            # Tightening the swapped-build branch above pushed three cases down into this
            # one — a missing version on either side, and a capped code digest — and this
            # line then asserted the version AND the program files were unchanged when one
            # was unrecorded and the other demonstrably differed. An `elif` chain makes
            # "the branch above did not fire" look like evidence; it never is.
            alerts.append((
                "INFO",
                "The set of packages OpenClaw depends on changed, with its own version and "
                "program files unchanged."))
        if _c_inst.get("code_capped"):
            note(NOTE_INSPECTION_CAPPED,
                 "Your OpenClaw installation is larger than one run inspects, so only part "
                 "of its program files were fingerprinted.")
