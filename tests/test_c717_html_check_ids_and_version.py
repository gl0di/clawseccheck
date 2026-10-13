"""C-717 - the HTML report carried no check id and no tool version.

The text report, `--save`, `--pdf`, `--sarif` and `--json` all name a finding by its
catalog id, and the text report itself sends the reader to `--html <path>` for the full
report and to `--explain <ID>` for one finding. The HTML page printed 19 WARN findings with
not one id on it, so a reader could not name the finding to explain, to put in
`.clawseccheckignore`, or to quote in an issue; and it carried no version, so a page kept
for months could not be tied to the build that wrote it.

What is pinned here: every finding row shows its id beside the title, the page shows the
tool version once, and nothing else about the page moves (no home path, no secret-shaped
value, no tracker-style id). New names are imported inside the tests so each one fails
behaviourally on the old code rather than at collection.

Offline, read-only outside tmp_path, stdlib + pytest only.
"""
from __future__ import annotations

import html as _html
import json
import re
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOMES = ("home_safe", "home_vuln")
_BASE = ["--no-native", "--no-host", "--no-history", "--no-deptree"]

_ID_SPAN_RE = re.compile(r'<span class="finding-id">([^<]*)</span>')
_STYLE_RE = re.compile(r"<style\b.*?</style>", re.S)
_HEAD_RE = re.compile(r"<head\b.*?</head>", re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def _visible_text(page: str) -> str:
    """The text a reader sees: no head (title/style), no tags, entities decoded."""
    body = _HEAD_RE.sub("", _STYLE_RE.sub("", page))
    return _html.unescape(_TAG_RE.sub(" ", body))


def _cli(tmp_path, capsys, home_name: str, *extra: str) -> str:
    from clawseccheck.cli import main
    capsys.readouterr()
    main(["--home", str(FIXTURES / home_name), *_BASE,
          "--data-dir", str(tmp_path / "state"), *extra])
    return capsys.readouterr().out


def _cli_pair(tmp_path, capsys, home_name: str) -> tuple[str, dict]:
    """The real CLI: the `--html` page and the `--json` payload of the same fixture."""
    out = tmp_path / f"{home_name}.html"
    _cli(tmp_path, capsys, home_name, "--html", str(out))
    payload = json.loads(_cli(tmp_path, capsys, home_name, "--json"))
    return out.read_text(encoding="utf-8"), payload


def _direct_pair(home_name: str) -> tuple[str, dict]:
    """`render_html` called directly on the same audit, beside the JSON of that audit."""
    from clawseccheck import audit
    from clawseccheck.report import render_html, render_json
    ctx, findings, score = audit(FIXTURES / home_name)
    return (render_html(findings, score, ctx=ctx),
            json.loads(render_json(findings, score)))


def _actionable(payload: dict) -> list[dict]:
    return [f for f in payload["findings"]
            if f["status"] in ("WARN", "FAIL") and not f.get("suppressed")]


def _assert_every_shown_finding_carries_its_id(page: str, payload: dict) -> None:
    shown = [f for f in _actionable(payload) if _html.escape(f["title"]) in page]
    # Positive control: the comparison below must not pass because nothing matched.
    assert len(shown) >= 3, [f["title"] for f in _actionable(payload)]
    ids_on_page = _ID_SPAN_RE.findall(page)
    assert ids_on_page, "the page carries no finding-id element at all"
    for f in shown:
        assert _html.escape(f["id"]) in ids_on_page, (f["id"], f["title"])
    # One id element per finding card, not a stray extra.
    assert len(ids_on_page) == page.count('<article class="finding')


@pytest.mark.parametrize("home_name", HOMES)
def test_cli_html_names_every_shown_finding_by_its_id(tmp_path, capsys, home_name):
    page, payload = _cli_pair(tmp_path, capsys, home_name)
    _assert_every_shown_finding_carries_its_id(page, payload)


@pytest.mark.parametrize("home_name", HOMES)
def test_render_html_names_every_shown_finding_by_its_id(home_name):
    page, payload = _direct_pair(home_name)
    _assert_every_shown_finding_carries_its_id(page, payload)


def test_the_id_sits_next_to_the_title_in_the_finding_head():
    from clawseccheck.catalog import MEDIUM, WARN, Finding
    from clawseccheck.report import render_html
    from clawseccheck.scoring import compute
    f = Finding(id="C015", title="Some check title", severity=MEDIUM, status=WARN,
                detail="d", fix="x", framework="")
    page = render_html([f], compute([f]))
    head = re.search(r'<div class="finding-head">(.*?)</div>', page, re.S).group(1)
    assert "Some check title" in head
    assert '<span class="finding-id">C015</span>' in head
    assert head.index("Some check title") < head.index("C015")


def test_the_id_is_escaped_like_every_other_field():
    from clawseccheck.catalog import MEDIUM, WARN, Finding
    from clawseccheck.report import render_html
    from clawseccheck.scoring import compute
    f = Finding(id="B5<img src=x>", title="t", severity=MEDIUM, status=WARN,
                detail="d", fix="x", framework="")
    page = render_html([f], compute([f]))
    assert "<img src=x>" not in page
    assert '<span class="finding-id">B5&lt;img src=x&gt;</span>' in page


@pytest.mark.parametrize("home_name", HOMES)
def test_cli_html_shows_the_tool_version_exactly_once(tmp_path, capsys, home_name):
    from clawseccheck import __version__
    page, payload = _cli_pair(tmp_path, capsys, home_name)
    assert payload["version"] == __version__
    assert _visible_text(page).count(__version__) == 1


def test_render_html_shows_the_tool_version_exactly_once_even_with_no_findings():
    from clawseccheck import __version__
    from clawseccheck.report import render_html
    from clawseccheck.scoring import compute
    page = render_html([], compute([]))
    assert _visible_text(page).count(__version__) == 1


@pytest.mark.parametrize("home_name", HOMES)
def test_ids_on_the_page_are_catalog_ids_and_no_tracker_ids_leak(tmp_path, capsys, home_name):
    from clawseccheck.catalog import BY_ID
    page, _payload = _cli_pair(tmp_path, capsys, home_name)
    ids_on_page = {_html.unescape(i) for i in _ID_SPAN_RE.findall(page)}
    assert ids_on_page, "positive control: the page must carry ids for this to mean anything"
    assert ids_on_page <= set(BY_ID), sorted(ids_on_page - set(BY_ID))
    # Control: no tracker-style id (B-586, C-717, E-038 ...) anywhere a reader can see.
    assert not re.search(r"\b[A-Z]{1,3}-\d{2,4}\b", _visible_text(page)), \
        "tracker-style id on the page"


@pytest.mark.parametrize("home_name", HOMES)
def test_the_page_still_carries_no_home_path_and_no_secret_shaped_value(
        tmp_path, capsys, home_name):
    page, _payload = _cli_pair(tmp_path, capsys, home_name)
    text = _visible_text(page)
    for needle in (str(Path.home()), str(FIXTURES), "/home/", "/Users/"):
        assert needle not in page and needle not in text, needle
    # Credential-shaped values the fixture itself holds must not have reached the page.
    cfg = json.loads((FIXTURES / home_name / "openclaw.json").read_text(encoding="utf-8"))
    secrets: list[str] = []

    def walk(node, key=""):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, str(k))
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
        elif (isinstance(node, str) and len(node) >= 12
              and re.search(r"token|secret|password|api_?key", key, re.I)):
            secrets.append(node)

    walk(cfg)
    for value in secrets:
        assert value not in page, "a configured credential value reached the page"
