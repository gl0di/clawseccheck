"""B-617: the audit says where it went, and the channel that says it cannot grow teeth.

Two things are pinned here, and the second matters more than the first.

**The fact.** When `agents.defaults.workspace` points outside the audited home, the collector
follows it (OpenClaw does too), reads skills and bootstrap files from there, and records that
it did. Before this change that record reached `--sarif` and nothing else: the default text
report and `--json` were silent, so a user who ran `clawseccheck --home X` was never told the
run read from outside `X`. Measured before the fix, on the home below: `--sarif` carried it,
the text report matched `custom workspace` zero times.

**The shape.** The fact is NOT a coverage gap. Those files WERE read — `ctx.installed_skills`
contains the out-of-home skill, and a malicious one produces a B13 FAIL naming it. So the
first draft of this task, which said "route it into the B-526 coverage channel and print it
under `Not assessed`", would have shipped the exact inverse of what happened. The heading
assertion below exists to stop that being "fixed" back.

**And the risk the design named as biggest.** `ctx.limit_hits` was a notepad too, until
`dossier.py` read its truthiness into a verdict leg — after which B-548's C-135 had to retract
an arm for writing to it. `_MODE_C_VERDICT` maps `UNKNOWN -> CAUTION`, so any status this
channel acquires becomes an install gate, which is the defect B-526 was filed to fix. A
comment cannot prevent that; `test_no_module_outside_the_renderers_reads_the_channel` can.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_PKG = _REPO / "clawseccheck"


def _home(tmp_path: Path, *, outside: bool) -> Path:
    """A scratch home whose config either does or does not reach outside itself."""
    home = tmp_path / "home"
    (home / "skills").mkdir(parents=True)
    if outside:
        ws = tmp_path / "outside"
        (ws / "skills" / "tidy").mkdir(parents=True)
        p = ws / "skills" / "tidy" / "SKILL.md"
        p.write_text(
            "---\nname: tidy\ndescription: Formats tables.\n---\n\n# tidy\n\nFormats tables.\n",
            encoding="utf-8",
        )
        os.chmod(p, 0o600)
        cfg = {
            "agents": {
                "list": [{"id": "main"}, {"id": "skills"}],
                "defaults": {"workspace": "../outside"},
            }
        }
    else:
        cfg = {}
    c = home / "openclaw.json"
    c.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(c, 0o600)
    return home


def _run(home: Path, tmp_path: Path, *extra: str) -> subprocess.CompletedProcess:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--home", str(home),
         "--data-dir", str(data), "--no-history", *extra],
        capture_output=True, text=True, cwd=str(_REPO),
    )


def test_the_audit_text_says_the_run_read_outside_the_scope(tmp_path):
    """The half that was missing. `--sarif` alone is not a disclosure to a human."""
    out = _run(_home(tmp_path, outside=True), tmp_path).stdout
    assert "Read outside the audited scope" in out, out[:2000]
    assert "does not affect the verdict" in out, out[:2000]
    assert "resolves outside the audited --home" in out, out[:2000]


def test_the_heading_does_not_claim_the_files_went_unread(tmp_path):
    """The correction this task turned on, pinned so it cannot be reverted by tidying.

    A `Not assessed` heading here would be a lying disclosure: worse than the silence it
    replaced, because a reader would conclude those files were never examined. They were —
    the assertion below proves the same run really did scan the out-of-home skill.
    """
    home = _home(tmp_path, outside=True)
    out = _run(home, tmp_path).stdout
    block = out.split("Read outside the audited scope", 1)[1].split("\n\n", 1)[0]
    assert "Not assessed" not in block, block

    sys.path.insert(0, str(_REPO))
    from clawseccheck import collector  # noqa: PLC0415

    ctx = collector.collect(str(home))
    assert "tidy" in (ctx.installed_skills or {}), (
        "non-vacuity: the out-of-home skill must actually have been read, or the heading "
        "argument above is moot"
    )


def test_no_absolute_path_reaches_any_rendered_surface(tmp_path):
    """`sarif.py` copies `ctx.limit_hits` verbatim and that entry interpolates the resolved
    absolute path, so `/home/<user>/...` already reaches SARIF today. The disclosure carries
    a bare name instead — `report._credential_surface_rel`'s precedent: say WHAT was found,
    never WHERE on disk."""
    home = _home(tmp_path, outside=True)
    text = _run(home, tmp_path).stdout
    payload = json.loads(_run(home, tmp_path, "--json").stdout)

    block = text.split("Read outside the audited scope", 1)[1].split("\n\n", 1)[0]
    assert not re.search(r"/home/|/tmp/|/Users/", block), block

    for d in payload["disclosures"]:
        for field in (d["subject"], d["detail"]):
            assert not re.search(r"/home/|/tmp/|/Users/", field), field
            assert os.sep not in field.replace("--home", ""), field


def test_the_channel_reaches_json_and_sarif_too(tmp_path):
    """Three surfaces, one source. A fact only one renderer carries is how B-553, B-616 and
    this bug each came to exist."""
    home = _home(tmp_path, outside=True)
    payload = json.loads(_run(home, tmp_path, "--json").stdout)
    kinds = {d["kind"] for d in payload["disclosures"]}
    assert kinds == {"workspace_outside_home"}, payload["disclosures"]

    sarif_path = tmp_path / "out.sarif"
    _run(home, tmp_path, "--sarif", str(sarif_path))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    recs = sarif["runs"][0]["properties"]["analysis_completeness"]["disclosures"]
    assert [d["kind"] for d in recs] == ["workspace_outside_home"] * len(recs)
    assert recs, "SARIF lost the channel it was already the only carrier of"


def test_a_home_that_stays_in_scope_says_nothing(tmp_path):
    """The negative control. Without it every assertion above could pass on a build that
    prints the block unconditionally."""
    out = _run(_home(tmp_path, outside=False), tmp_path).stdout
    assert "Read outside the audited scope" not in out, out[:2000]


def test_the_json_key_is_present_and_empty_rather_than_absent(tmp_path):
    """B-560's lesson: a consumer cannot tell an absent key from 'nothing to report'."""
    payload = json.loads(_run(_home(tmp_path, outside=False), tmp_path, "--json").stdout)
    assert "disclosures" in payload, sorted(payload)
    assert payload["disclosures"] == []


def test_the_disclosure_moves_neither_verdict_nor_exit_code(tmp_path):
    """The B-526 contract, restated for this channel.

    Asserted against a CONTROL run rather than against literals, because the interesting
    property is 'identical to what it would have been', not any particular value.
    """
    outside = _home(tmp_path / "a", outside=True)
    plain = _home(tmp_path / "b", outside=False)
    r_out = _run(outside, tmp_path, "--json")
    r_in = _run(plain, tmp_path, "--json")
    assert r_out.returncode == r_in.returncode == 0, (r_out.returncode, r_in.returncode)

    a, b = json.loads(r_out.stdout), json.loads(r_in.stdout)
    for key in ("score", "grade", "graded"):
        assert a[key] == b[key], f"{key}: {a[key]!r} vs {b[key]!r}"
    # The disclosure is the ONLY difference the out-of-home config makes to the payload's
    # verdict fields; the finding population may legitimately differ, so it is not compared.
    assert a["disclosures"] and not b["disclosures"]


def test_no_module_outside_the_renderers_reads_the_channel():
    """The mechanical mitigation, and the reason this file exists at all.

    `ctx.limit_hits` began as bookkeeping and acquired verdict weight when `dossier.py`
    started reading its truthiness — after which writing to it changed verdicts, and B-548's
    C-135 had to retract an arm that treated it as a notepad. Nothing structural stopped
    that, and nothing structural would stop it happening to `ctx.disclosures` in six months.
    This test is that structure: the channel may be WRITTEN by the collector and READ only by
    the renderers. A check reading it would let a disclosure reach a verdict, and
    `_MODE_C_VERDICT` maps `UNKNOWN -> CAUTION`, so it would gate an install.

    If a new renderer legitimately needs the channel, add it here deliberately.
    """
    allowed = {"collector.py", "report.py", "sarif.py"}
    offenders = []
    for py in sorted(_PKG.rglob("*.py")):
        rel = py.relative_to(_PKG).as_posix()
        if py.name in allowed and "/" not in rel:
            continue
        src = py.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"\.disclosures\b|[\"']disclosures[\"']", src):
            line = src[: m.start()].count("\n") + 1
            offenders.append(f"{rel}:{line}")
    assert not offenders, (
        "ctx.disclosures is read outside the collector and the renderers: "
        + ", ".join(offenders)
        + " — a disclosure that reaches a check can reach a verdict, and a verdict gates an "
          "install. Add the module to `allowed` only if it is genuinely a renderer."
    )


@pytest.mark.parametrize("kind", ["workspace_outside_home"])
def test_every_kind_has_a_heading_of_its_own(kind):
    """A kind falling through to the generic heading is the bug this channel exists to avoid
    repeating: one heading for facts that mean opposite things."""
    sys.path.insert(0, str(_REPO))
    from clawseccheck.report import _DISCLOSURE_HEADINGS  # noqa: PLC0415

    assert kind in _DISCLOSURE_HEADINGS, sorted(_DISCLOSURE_HEADINGS)
    assert "not assessed" not in _DISCLOSURE_HEADINGS[kind].lower()
