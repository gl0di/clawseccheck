"""CLAWSECCHECK-B-825: `--json` and `--html` must agree on home-path redaction.

`report._redact_home_paths` (B-381) already ran on every string in the `--json` tree
family (`_sanitize_tree`, C-456) and on `--pdf`'s one "Why:" line (same C-456 commit),
but `render_html`'s `_finding_card` never called it -- so a `Finding.detail`/`evidence`
string containing a real, unredacted absolute home path (e.g. what
`checks/_shared.py::_username_safe_path` returns verbatim when it cannot collapse a
path against a `$HOME` that has been spoofed away from the real account home) reached
`--html` raw while `--json` correctly folded it to `~`.

Two levels, matching the two existing sibling suites this mirrors:

* `test_c456_json_pdf_path_redaction.py`'s own pattern -- a directly-constructed,
  C5-shaped Finding carrying a literal `/home/<user>/...` path, asserting the renderer
  under test never emits the raw prefix. Extended here to `render_html`.
* The literal reproduction from the bug report: a `$HOME` spoofed to a directory that
  is NOT the real account home, so `_username_safe_path` declines to collapse a
  real-home-shaped path and hands it back verbatim -- then `--json` and `--html` are
  rendered from the SAME Finding and asserted to redact identically.

Offline, deterministic, stdlib + pytest only.
"""
from __future__ import annotations

from clawseccheck.catalog import HIGH, WARN, Finding
from clawseccheck.checks._shared import _username_safe_path
from clawseccheck.report import render_html, render_json
from clawseccheck.scoring import compute

# Synthetic, matching test_c456_json_pdf_path_redaction.py's own constant -- never
# Path.home(), so this assertion cannot pass vacuously under any HOME-isolation fixture.
_FAKE_HOME_PREFIX = "/home/faketestuser"
_LEAKY_PATH = f"{_FAKE_HOME_PREFIX}/.npm-global/lib/node_modules/openclaw"


def _c5_shaped_finding(*, detail: str, evidence: list) -> Finding:
    """A Finding shaped like C5's real WARN output (checks/_capability.py's
    check_path_safety), matching test_c456_json_pdf_path_redaction.py's own fixture."""
    return Finding(
        id="C5", title="Native binary PATH safety", severity=HIGH, status=WARN,
        detail=detail, fix="fix text", framework="", evidence=evidence,
    )


def test_render_html_never_carries_the_home_path_in_detail():
    f = _c5_shaped_finding(
        detail=f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable",
        evidence=[],
    )
    page = render_html([f], compute([f]))
    assert _FAKE_HOME_PREFIX not in page, page
    assert "npm-global" in page, "redaction, not deletion -- the remainder must survive"


def test_render_html_never_carries_the_home_path_in_evidence():
    """Distinct from `detail` -- `_finding_card` builds its evidence list through a
    separate code path (`_evidence_bullets`) that must get the same redaction."""
    f = _c5_shaped_finding(
        detail="see evidence below",
        evidence=[f"openclaw binary dir {_LEAKY_PATH}/bin is world-writable"],
    )
    page = render_html([f], compute([f]))
    assert _FAKE_HOME_PREFIX not in page, page
    assert "npm-global" in page, "redaction, not deletion -- the remainder must survive"


def test_evidence_dedup_against_detail_still_works_after_redaction():
    """The `already_shown` cap/dedup in `_finding_card` compares evidence against
    `detail` BEFORE the final redaction pass. If redaction ran first, a real-home path
    collapsed to `~` in `detail` would stop matching the still-raw copy in `evidence`,
    and the entry would wrongly print twice."""
    same_text = f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable"
    f = _c5_shaped_finding(detail=same_text, evidence=[same_text])
    page = render_html([f], compute([f]))
    # The (redacted) sentence appears once for `detail`; the evidence list must not
    # repeat it as a bullet (would show as a second occurrence of "group-writable").
    assert page.count("group-writable") == 1, page


def test_json_and_html_agree_when_home_is_spoofed_away_from_the_real_account_home(
    monkeypatch, tmp_path,
):
    """The bug's literal reproduction: `$HOME` points somewhere that is NOT the real
    account home, so `_username_safe_path` correctly declines to collapse a
    real-home-shaped path and returns it verbatim -- the exact input `--json`'s
    `_sanitize_tree` and `--html`'s `_finding_card` must now both catch."""
    spoofed_home = tmp_path / "not-the-real-home"
    spoofed_home.mkdir()
    monkeypatch.setenv("HOME", str(spoofed_home))
    monkeypatch.setenv("USERPROFILE", str(spoofed_home))

    real_account_path = f"{_FAKE_HOME_PREFIX}/.npm-global/lib/node_modules/openclaw"
    # Confirm the premise: with HOME spoofed elsewhere, _username_safe_path really
    # does hand back the real-home path verbatim (declines to collapse it) --
    # otherwise this test would prove nothing about the divergence it targets.
    rendered = _username_safe_path(real_account_path)
    assert rendered == real_account_path, (
        "premise broken: _username_safe_path collapsed a path outside the spoofed "
        f"HOME, so this test no longer exercises the B-825 scenario (got {rendered!r})"
    )

    f = _c5_shaped_finding(
        detail=f"openclaw binary dir {rendered} is group-writable",
        evidence=[f"openclaw binary dir {rendered} is group-writable"],
    )
    score = compute([f])
    json_doc = render_json([f], score)
    html_doc = render_html([f], score)

    assert _FAKE_HOME_PREFIX not in json_doc, json_doc
    assert _FAKE_HOME_PREFIX not in html_doc, (
        "B-825: --html leaked the real account home path under a spoofed $HOME "
        f"while --json correctly redacted it -- {html_doc}"
    )
    assert "~/.npm-global" in json_doc, json_doc
    assert "~/.npm-global" in html_doc, html_doc
