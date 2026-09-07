"""The HTML report must carry a finding's evidence, and say how sure the engine is.

B-622. `render_html` contained **zero** references to `.evidence` and zero to `confidence`,
so no finding's evidence reached the page through the evidence channel and a hedged FAIL
rendered identically to a certain one.

What made it worth fixing rather than filing as cosmetic is what the measurement showed. On a
deliberately-bad config, of 24 evidence entries **12 appeared on the page anyway** — every one
of them only because its check had joined the same words into `detail` — and 12 never appeared
at all, including the evidence behind a FAIL. So the page was not cleanly missing a channel:
it looked like it carried evidence, and which half a reader got depended on how each check
happened to build its `detail`. A clean absence is easier to notice than a half-present one.

The cap decision is taken by the shared `_evidence_bullets` helper rather than re-decided
here. B-629 is the record of what three independent copies of that decision cost: the same
"print at most N" rule made in three places and announced in one.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import html as _html
import json
import subprocess
import sys

_BAD_CONFIG = {
    # `groups: {"*": {}}` is here to make ONE finding in this probe deliberately hedged
    # (B140, confidence MEDIUM, surface "channels"). Without it the only non-HIGH-confidence
    # finding came from C5 — "Native binary PATH safety", surface "host" — which stats the
    # real machine's PATH. It fires on a developer box and not on a GitHub runner, so the
    # hedged-pill test below passed locally and failed on all three CI jobs.
    "channels": {"telegram": {"enabled": True, "dmPolicy": "open", "allowFrom": ["*"],
                              "groups": {"*": {}}}},
    "tools": {"allow": ["read_file", "web_fetch", "exec_command"], "exec": {"mode": "full"}},
    "gateway": {"bind": "0.0.0.0"},
}


def _render(tmp_path, config):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    out_html = tmp_path / "out.html"
    common = ["--home", str(home), "--data-dir", str(tmp_path / "d"), "--no-history"]
    subprocess.run([sys.executable, "-m", "clawseccheck", *common, "--html", str(out_html)],
                   capture_output=True, text=True, check=False)
    payload = subprocess.run([sys.executable, "-m", "clawseccheck", *common, "--json"],
                             capture_output=True, text=True, check=False).stdout
    return out_html.read_text(encoding="utf-8"), json.loads(payload)


def _in_html(entry: str, page: str) -> bool:
    probe = entry[:40]
    return probe in page or _html.escape(probe) in page


def test_every_actionable_findings_evidence_reaches_the_page(tmp_path):
    """The defect, asserted on the population it was measured on."""
    page, payload = _render(tmp_path, _BAD_CONFIG)

    actionable = [f for f in payload["findings"] if f["status"] in ("FAIL", "WARN")]
    entries = [e for f in actionable for e in (f.get("evidence") or [])]

    # Non-vacuity: a config that produced no actionable evidence would make every
    # assertion below pass while proving nothing.
    assert len(entries) > 10, f"probe produced only {len(entries)} evidence entries"

    missing = [e for e in entries if not _in_html(e, page)]
    assert not missing, f"{len(missing)} evidence entries absent from the HTML: {missing[:3]}"


def test_a_fails_evidence_is_present_which_is_the_case_that_was_absent(tmp_path):
    """Named separately because it is the concrete harm: before this change, a FAIL's
    evidence was among the entries that never reached the page."""
    page, payload = _render(tmp_path, _BAD_CONFIG)
    fails = [f for f in payload["findings"] if f["status"] == "FAIL" and f.get("evidence")]
    assert fails, "probe produced no FAIL carrying evidence"
    for f in fails:
        for e in f["evidence"]:
            assert _in_html(e, page), (f["id"], e)


def test_a_hedged_finding_is_distinguishable_from_a_certain_one(tmp_path):
    """Same condition the text report applies: tag when confidence is not HIGH and the
    finding is actionable."""
    page, payload = _render(tmp_path, _BAD_CONFIG)
    hedged = [f for f in payload["findings"]
              if f["status"] in ("FAIL", "WARN") and f.get("confidence") not in (None, "HIGH")]
    # The hedged finding must come from the CONFIG, not from the machine. Excluding the host
    # surface is what makes this test mean the same thing everywhere: the earlier version
    # took whatever was hedged, which on a developer box was C5 (host PATH permissions) and
    # on a GitHub runner was nothing at all — green locally, red on all three CI jobs.
    hedged = [f for f in hedged if f.get("surface") != "host"]
    assert hedged, (
        "probe produced no non-HIGH actionable finding from the config itself — the "
        "hedged-pill assertion below would be testing nothing"
    )
    assert "conf-pill" in page
    assert f"confidence: {hedged[0]['confidence'].lower()}" in page


def test_evidence_is_html_escaped(tmp_path):
    """New attacker-influenced text is being put into a page. A skill author controls parts
    of what lands in `evidence`, so the escaping is asserted rather than assumed."""
    config = dict(_BAD_CONFIG)
    config["channels"] = {
        "telegram": {"enabled": True, "dmPolicy": "open",
                     "allowFrom": ["<script>alert(1)</script>"]},
    }
    page, _payload = _render(tmp_path, config)
    assert "<script>alert(1)</script>" not in page
    if "alert(1)" in page:
        assert "&lt;script&gt;" in page, "unescaped markup reached the page"


def test_the_blocks_appear_only_where_there_is_something_to_show(tmp_path):
    """The control. If either block appeared on every card it would carry no information.

    Asserted as a RELATIONSHIP against the payload rather than by declaring some config
    "clean". Two earlier drafts of this control were wrong in different ways and both are
    worth recording: the first checked for the class NAME, which occurs in the stylesheet
    on every page regardless of content — a control measuring the wrong object; the second
    assumed a minimal config produces no actionable findings, and it produces six.
    """
    page, payload = _render(tmp_path, {"channels": {}, "tools": {"allow": ["read_file"]}})
    actionable = [f for f in payload["findings"] if f["status"] in ("FAIL", "WARN")]
    assert actionable, "probe produced nothing actionable — the relationship is vacuous"

    with_evidence = [f for f in actionable if f.get("evidence")]
    non_high = [f for f in actionable if f.get("confidence") not in (None, "HIGH")]

    # A block per card at most, and never for a card that has nothing to put in it.
    assert page.count('<ul class="finding-evidence">') <= len(with_evidence)
    assert page.count('<span class="conf-pill">') == len(non_high)
