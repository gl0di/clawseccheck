"""B-738: a remediation must clear the condition its own finding describes.

The defect. RISK-03's chain is "no sandbox + untrusted ingress + exec/write **on the host**",
and its fix said: set `agents.defaults.sandbox.mode` to `'non-main'` or `'all'`. Measured by
running the engine, both values cleared it. But OpenClaw keeps the agent's own MAIN session on
the host under `non-main` — `dist/launch-BmPwk1y9.js:37`, quoted in `risk.py`'s own containment
docstring — so the chain is still live after the user does what the finding told them.

That is worse than the B-714 class it resembles. B-714's advice named a key the schema rejects,
so a user following it got a config OpenClaw refused to load: loud, immediate, self-correcting.
This advice is accepted, the finding disappears, and the exposure does not. The user is told
they fixed it and the tool agrees.

Six sites offered it, and the worst was `catalog.py`'s STRUCTURED remediation — the one an
automated fixer or a host agent applies without reading prose — whose note read "run exec tools
in a sandbox".

THE ROOT WAS AN INTERNAL DISAGREEMENT, WHICH IS WHY A GUARD IS WORTH MORE THAN THE SIX FIXES
--------------------------------------------------------------------------------------------
`risk.py`'s containment predicate already required exactly `"all"` and cited the dist for why,
since 2026-08-24. Six remediations offered `non-main` as equivalent. One module was right and
the others were wrong about the same vendor behaviour, and nothing compared them. B-712 found
the identical split in `toolpolicy.py`, which read "non-main" as "not the main AGENT" rather
than "not the main SESSION" — three modules, two readings, no cross-check.

So these tests do not re-assert the six strings. They assert the RELATIONSHIP: every sandbox
value the tree recommends must satisfy the tree's own containment predicate.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from clawseccheck.catalog import REMEDIATION
from clawseccheck.checks import run_all
from clawseccheck.collector import collect
from clawseccheck.risk import risk_paths

REPO = Path(__file__).resolve().parent.parent

# Every sandbox mode the vendor accepts, and whether it contains the agent's own MAIN session —
# the session an operator actually drives. Grounded by executing `resolveSandboxRuntimeStatus`
# from the installed 2026.9.1 for both session positions (see tests/data/sandbox_battery.json):
# under "non-main" that agent's own main session comes back sandboxed=False.
_CONTAINS_MAIN_SESSION = {"all": True, "non-main": False, "off": False}

# The modules that hand a sandbox value to a user.
_ADVICE_SOURCES = (
    "clawseccheck/catalog.py",
    "clawseccheck/risk.py",
    "clawseccheck/checks/_config.py",
)

# A recommendation looks like "set ... sandbox.mode to 'X'" / "sandbox.mode to 'X'/'Y'".
_RECOMMENDS = re.compile(
    r"sandbox\.mode[^.\n]{0,60}?to\s+((?:'[a-z-]+'(?:\s*/\s*)?)+)", re.I
)


def _fires_risk03(cfg: dict) -> bool:
    home = Path(tempfile.mkdtemp(prefix="b738-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg))
    os.chmod(path, 0o600)
    ctx = collect(str(home))
    return any(r.id == "RISK-03" for r in risk_paths(ctx, run_all(ctx)))


_UNSANDBOXED = {
    "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
    "tools": {
        "profile": "full",
        "exec": {"security": "full"},
        "allow": ["exec", "write", "read", "edit", "apply_patch"],
    },
}


def test_the_structured_b4_remediation_names_a_mode_that_contains_the_main_session():
    """`catalog.py`'s REMEDIATION entries are machine-applicable — a fixer writes the value
    without reading the note. It said `non-main`, which does not do what its note promised."""
    entry = REMEDIATION["B4"]["config"][0]
    assert entry["path"] == "agents.defaults.sandbox.mode", entry
    assert _CONTAINS_MAIN_SESSION.get(entry["set"]) is True, (
        f"the structured B4 remediation sets {entry['set']!r}, which leaves the agent's own "
        "main session on the host — the session exec actually runs in"
    )
    assert "non-main" in entry["note"], (
        "the note must still name the value it is steering away from, or a reader who "
        "already set 'non-main' has no way to learn it is insufficient"
    )


def test_no_shipped_advice_recommends_a_mode_that_leaves_the_main_session_on_the_host():
    """The relationship guard, and the reason this file exists rather than six edited strings.

    `risk.py`'s containment predicate has required exactly "all" since 2026-08-24, citing the
    dist. Six remediations disagreed with it. Nothing compared them — so the tree held two
    readings of one vendor behaviour and stayed green.
    """
    offenders = []
    for rel in _ADVICE_SOURCES:
        text = (REPO / rel).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue  # a comment explaining what NOT to recommend is not a recommendation
            for match in _RECOMMENDS.finditer(line):
                for value in re.findall(r"'([a-z-]+)'", match.group(1)):
                    if _CONTAINS_MAIN_SESSION.get(value) is False:
                        offenders.append(f"{rel}:{lineno}: recommends {value!r}")
    assert not offenders, (
        "advice recommends a sandbox mode that does not contain the agent's own main "
        "session:\n  " + "\n  ".join(offenders) + "\n\nOnly 'all' does. A value that clears "
        "the finding without closing the hole is worse than no advice."
    )


def test_the_advice_guard_bites_on_the_string_it_replaced():
    """Positive control. Without it the sweep above passes against a regex that matches
    nothing — which is indistinguishable from a tree with no bad advice in it."""
    retired = "Set agents.defaults.sandbox.mode to 'non-main' or 'all'"
    found = [
        v
        for m in _RECOMMENDS.finditer(retired)
        for v in re.findall(r"'([a-z-]+)'", m.group(1))
    ]
    assert "non-main" in found, found
    assert any(_CONTAINS_MAIN_SESSION.get(v) is False for v in found)


def test_following_risk03_advice_actually_clears_its_own_chain():
    """The behavioural half: apply the recommended value and check the condition is gone.

    This is the general property that failed — and the one that would have caught B-714 too,
    where the recommended key made the config unloadable. Here `all` must clear RISK-03 and
    the config must be one that fires it to begin with, or the assertion is vacuous.
    """
    assert _fires_risk03(_UNSANDBOXED), "precondition: the bare config must fire RISK-03"
    fixed = dict(_UNSANDBOXED)
    fixed["agents"] = {"defaults": {"sandbox": {"mode": "all"}}}
    assert not _fires_risk03(fixed), "'all' must clear the chain it is recommended for"


def test_non_main_still_clears_risk03_today_and_that_is_recorded_not_fixed():
    """The residual, pinned deliberately so it is not mistaken for closed.

    B-738 fixed the ADVICE. It did not change what CLEARS the finding: a user who chooses
    `non-main` on their own still gets a clean RISK-03 while their main session runs on the
    host. Changing that moves verdicts on 33 of the 36 corpus fixtures that use `non-main`
    (B4 PASS today), so it is a separate decision with its own C-135, not a rider on a
    wording fix.

    If this test starts failing, the verdict half has been done — update it rather than
    restoring the old behaviour.
    """
    partial = dict(_UNSANDBOXED)
    partial["agents"] = {"defaults": {"sandbox": {"mode": "non-main"}}}
    assert not _fires_risk03(partial), (
        "expected the KNOWN residual: 'non-main' still clears RISK-03. If this now fires, "
        "the verdict half of B-738 has landed and this test should be updated to match."
    )


def test_no_generated_remediation_leaks_python_source():
    """B-738, second half: a fix string that resolves at RUNTIME must not reach the docs as
    source code.

    `docs/CHECKS.md` is generated by AST-walking `catalog.py` and `risk.py`. Its extractor
    falls back to `ast.unparse` for any expression it does not model, so when B-714 made
    RISK-15's fix call `_key_advice(ctx, legacy, modern)` the shipped catalog told readers to
    set `_key_advice(ctx, 'browser.ssrfPolicy.hostnameAllowlist', ...)`. Nothing caught it —
    it surfaced only because markdownlint read the leading underscore as an emphasis marker.

    Cheap, total, and not tied to `_key_advice`: any private helper, `ctx.` access or
    Python-call shape inside rendered remediation prose is the same defect.
    """
    text = (REPO / "docs" / "CHECKS.md").read_text(encoding="utf-8")
    leaks = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "|")) or "`clawseccheck/" in line:
            continue  # code fences and source-file links are legitimately code-shaped
        for pattern in (r"\b_[a-z][a-z0-9_]*\s*\(", r"\bctx\.[a-z_]+", r"\bdig\s*\("):
            if re.search(pattern, line):
                leaks.append(f"{lineno}: {line.strip()[:110]}")
                break
    assert not leaks, (
        "generated remediation text contains Python source — the doc extractor hit an "
        "expression it does not model and unparsed it:\n  " + "\n  ".join(leaks)
    )


def test_the_source_leak_guard_bites_on_the_text_that_shipped():
    """Positive control, using the line that actually reached `docs/CHECKS.md`.

    Without this the sweep above passes on a tree with no leak AND on a tree whose patterns
    match nothing — indistinguishable from one green run.
    """
    shipped = (
        "  with an explicit _key_advice(ctx, 'browser.ssrfPolicy.hostnameAllowlist',"
    )
    assert re.search(r"\b_[a-z][a-z0-9_]*\s*\(", shipped), "the helper-call pattern must match"
    assert re.search(r"\bctx\.[a-z_]+", "  reads ctx.config for the value") is not None
    # and the corrected text must NOT match, or the guard would fail the fixed tree
    fixed = (
        "  with an explicit browser.ssrfPolicy.allowedHostnames (OpenClaw 2026.8.1 and "
        "later; browser.ssrfPolicy.hostnameAllowlist before it)."
    )
    assert not re.search(r"\b_[a-z][a-z0-9_]*\s*\(", fixed), fixed
