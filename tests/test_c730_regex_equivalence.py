"""C-730: the linear-time rewrites match what the old patterns matched.

Every pattern C-730 touched is pinned in ``tests/c730_old_patterns.json`` with the text and
flags it had before (taken from the tree as it was; two are derived from the new text
instead, see ``DERIVED``) and compared with what ships now. The comparison is as strict as
the call sites allow, and each relaxation is named:

``spans``      identical ``[(span, groups)]`` from ``finditer``.
``startfree``  the same matches with the same END, groups, group positions and stripped text;
               only where the match BEGINS may differ (a leading blank run that no longer
               reaches back over earlier lines). Every call site reads a group or
               ``group(0).strip()``.
``truth``      the same truth value from ``search`` (the one call site is a boolean test).
``first``      the same first match from ``search`` (every call site is ``.search``).
``urlsub``     the same text after the one substitution the pattern is used for.
``shrun``      the same commands with the same ``path``, and the old match start recovered
               by ``_sh_run_stmt_start`` (the reported line number comes from it).
``jsbrace``    identical unless the OLD name list held a "{" (see the pattern's comment).
``reference``  the pattern is kept verbatim as a definition and is no longer run over text;
               the one-pass scanner that replaced it must yield exactly its matches.

The corpus for each: every text file under ``fixtures/``, the adversarial units, targeted
seeds with random edits, and random strings over the pattern's own vocabulary.
"""
from __future__ import annotations

import importlib
import json
import random
import re
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PINS = json.loads((ROOT / "tests" / "c730_old_patterns.json").read_text(encoding="utf-8"))

BULLET, NBSP, EACUTE, CJK = chr(0x2022), chr(0xA0), chr(0xE9), chr(0x4E2D)
LONG_S, KELVIN, EM_SPACE, DOTTED_I = chr(0x17F), chr(0x212A), chr(0x2003), chr(0x130)

# Old text derived from the new one (with a uniqueness assert) instead of pinned: the host
# pattern is rebuilt from the bundled IOC dataset, and the destination pattern is one long
# normalised string.
DERIVED = {
    "checks._shared._KNOWN_EXFIL_HOST_RE": ("[a-z0-9-]{1,63}", "[a-z0-9-]+", 2, "host63"),
    "checks._content._B63_DEST_RE": (r"(?<![\w.+-])[\w.+-]+@[\w-]+\.[\w.-]+",
                                     r"[\w.+-]+@[\w-]+\.[\w.-]+", 1, "first"),
}


def _new(name: str):
    mod, attr = name.rsplit(".", 1)
    return getattr(importlib.import_module("clawseccheck." + mod), attr)


def _old(name: str) -> "re.Pattern":
    if name in DERIVED:
        fragment, was, count, _mode = DERIVED[name]
        new = _new(name)
        assert new.pattern.count(fragment) == count, f"{name}: the rewritten leg changed shape"
        return re.compile(new.pattern.replace(fragment, was), new.flags)
    pin = PINS[name]
    return re.compile(pin["pattern"], pin["flags"])


def _mode(name: str) -> str:
    return DERIVED[name][3] if name in DERIVED else PINS[name]["mode"]


REGEX_PAIRS = sorted([n for n, p in PINS.items() if p["mode"] != "reference"] + list(DERIVED))

GEN = [" ", "  ", "\t", "\n", "\n\n", " \n", "\r\n", "x", "a", "A", "0", "9", "/", ".", "-", "_",
       "=", ":", "~", "+", "@", "#", "!", "|", ">", "*", "[", "]", "(", ")", "{", "}", '"', "'",
       "`", ",", ";", "$", "\\", "%", "&", "?", "<", "http://", "https://", "a.b", "x.y.z", "~/",
       "/x/", "a-b", EACUTE, CJK, BULLET, NBSP, EM_SPACE, "1.", "2)", "- ", "* ", "| ", "> ",
       "import ", "to ", "the ", "my "]

SEEDS = {
    "_B164_NOT_SCANNED_RE": ["3 log/transcript sinks not scanned", "12 log/transcript sink not scanned"],
    "_B164_SQLITE_UNSCANNED_RE": ["40 row(s) across 3 session(s) unexamined"],
    "_B164_SQLITE_TRANSCRIPT_RE": ["7 transcript row(s) across 2 session(s) unexamined"],
    "_B164_SQLITE_TRANSCRIPT_DB_RE": ["2 per-agent database(s) could not be examined for transcripts"],
    "_TRACKER_CONNECTOR_RE": [" via B-123", " since CLAWSECCHECK-C-45", "  per E-012/W3.1 item 4",
                              " of F-1234 round 2", "\tfrom I-22 Phase 3", " via B-12 bug 7"],
    "_SSH_R_SPEC_RE": ["8080:localhost:22", ":host:80", "a:b:c:d:1", "[::1]:x:9", "1:2:x", "x:y:", "::1"],
    "_OPENCLAW_CRED_STORE_RE": ["discord-allowFrom.json", "x.y-pairing.json", "-pairing.json",
                                "a-allowfrom.jsonl"],
    "_FM_HOMEPAGE_RE": ["homepage: https://x.io", "\n\n  repository : 'https://a.b/c'",
                        "api_url: http://h", "url:\nhttps://z", 'base-url:"https://q.w#f"'],
    "_SKILL_VERSION_RE": ["version: 1.2.3", "\n\n version: 'v2'\n", "Version:\n 3",
                          "version: 1.0 \n\n", 'version:"1+b"'],
    "_SYSTEMD_EXECSTART_RE": ["ExecStart=/usr/bin/x --y", "\n\n  ExecStart = a b \n", "ExecStart=\n/bin/z",
                              "execstart="],
    "_SYSTEMD_RESTART_RE": ["Restart=always", "\n\n  Restart = on-failure \n", "Restart=\nno"],
    "_SYSTEMD_WANTEDBY_RE": ["WantedBy=default.target", "\n \n\tWantedBy = multi-user.target\n"],
    "_F052_NONBREAK_RE": ["e.g.", "a.b.c.", "i.e.", "x.", "U.S.A.", "etc.", "approx.", "see a.b.", "ab.c."],
    "_RUNTIME_FETCH_TABLE_DELIM_LINE_RE": ["|---|---|", " :-- | --: ", "---", "| - |", "|:-:|:-:|  ",
                                           "- | -", "|-"],
    "_B61_TOOL_DECL_RE": ["allowed-tools: Bash, Read", "  - tools: x", "* disallowed_tools : y",
                          "\ttools:", "-tools: z", " -  * tools: q"],
    "_SH_CASE_WILDCARD_ARM_RE": [" * )", "(*)", "\n ( * )", "*)", "( *", " (  \n*\n)"],
    "_PTH_IMPORT_LINE_RE": ["import os", "\n\n   import  x", "x\n import\ty", "import\n\nz"],
    "_PYPROJECT_DEP_LINE_RE": ["requests", '\n\n  "flask>=2"', "numpy == *", "pkg @ latest", "a[b,c] > 1",
                               "x\n\n\ny"],
    "_REQ_UNPINNED_RE": ["requests", "  flask>=2", "numpy == *", "pkg @ latest", "-r other.txt", "# c",
                         "a[b] >1\n\n"],
    "_DEP_PKG_NAME_RE": ["requests==1", "  flask", "-e .", "#x", "a.b-c_d"],
    "_URL_SHAPE_RE": ["https://u:p@h/x?y=1", "9http://a.b", "git+ssh://x", "a1+b.c-d://q", "..ftp://z",
                      "x://", "://y"],
    "_SH_RUN_PATH_RE": ["bash x.sh", "\n\n  sudo sh ./a/b", "; python3 run.py", "then  source ~/.x",
                        "do\n\n node s.js", "|| . ./env", "else\tperl p.pl", "xthen bash q.sh",
                        "&&\n\n\n ruby r.rb", "bash then\nbash sh"],
    "_JS_CP_DESTRUCTURE_BIND_RE": ["const { exec } = require('child_process')",
                                   'import { spawn as s, exec } from "node:child_process"',
                                   '{a,b}=require("child_process")'],
    "_KNOWN_EXFIL_HOST_RE": ["abc.ngrok.io", "a-b.ngrok-free.app", "x.pipedream.net", "pastebin.com",
                             "ngrok.io", "-a.ngrok.app", "_a.ngrok.io", "eo1.m.pipedream.net",
                             "A-B.Ngrok.App", "a" * 63 + ".ngrok.app"],
    "_SECRET_PATH_RE": ["~/.config/api_key/x.json", "my_password.", "a.b.c/secret-d", "tokens"],
    "_B58_URL_OR_EMAIL_RE": ["a.b+c@x-y.org", "http://x", "..@x.co", ".+a@b.cc", "a@b"],
    "_B63_DEST_RE": ["send to me at a@b.co", "to my server", "https://x.io", "x@y.zz+q@r.ss"],
}

UNITS = ["x", "a", "0", "_", "/", ".", "-", "+", "~", "@", " ", "\t", "\n", " \n", "a.", "a/", "a-",
         ".x", "x.y", ":", "{", "[", "<", "http://", EACUTE]


def _vocab(pattern: str) -> list:
    words = set(re.findall(r"[A-Za-z][A-Za-z0-9_]{1,}", pattern))
    words |= {w.replace("_", "-") for w in words}
    words |= {w.replace("\\.", ".") for w in re.findall(r"[a-z0-9-]+(?:\\\.[a-z0-9-]+)+", pattern)}
    return sorted(words)


def _mutate(s: str, rnd: random.Random) -> str:
    for _ in range(rnd.randint(0, 3)):
        if not s:
            break
        i = rnd.randrange(len(s) + 1)
        r = rnd.random()
        if r < 0.3:
            s = s[:i] + rnd.choice(GEN) + s[i:]
        elif r < 0.5:
            s = s[:i] + s[i + 1:]
        elif r < 0.7 and i < len(s):
            s = s[:i] + s[i] * rnd.randint(2, 6) + s[i + 1:]
        elif r < 0.85:
            s = s[:i] + rnd.choice([" ", "\n", "\t", "  ", "\n\n"]) * rnd.randint(1, 4) + s[i:]
        else:
            s = s[:i] + rnd.choice("0123456789:.-_{[(|") * rnd.randint(1, 5) + s[i:]
    return s


def _strings(short: str, pattern: str, n: int, seed: int = 730) -> list:
    rnd = random.Random(f"{seed}:{short}")
    words = _vocab(pattern)
    pool = GEN + words * 3
    seeds = SEEDS.get(short)
    out = []
    for _ in range(n):
        k = rnd.randint(1, 12)
        if seeds and rnd.random() < 0.6:
            s = rnd.choice(["", "", " ", "\n", "x", "9", "\n\n\n", "a b "]) + rnd.choice(
                ["", " ", "\n", "\n\n", ";", "x"]).join(
                    _mutate(rnd.choice(seeds), rnd) for _ in range(rnd.randint(1, 3)))
        elif words and rnd.random() < 0.4:
            parts = [rnd.choice(words) if rnd.random() < 0.7 else rnd.choice(GEN) for _ in range(k)]
            s = rnd.choice(["", " ", "\n", "12 ", "x"]) + rnd.choice([" ", " ", "", "\n", "  "]).join(parts)
        else:
            s = "".join(rnd.choice(pool) for _ in range(k))
        out.append(s)
    return out + list(seeds or []) + [u * 300 for u in UNITS]


_FIXTURES: list = []


def _fixture_texts() -> list:
    if not _FIXTURES:
        for p in sorted((ROOT / "fixtures").rglob("*")):
            try:
                if p.is_file() and p.stat().st_size <= 20_000:
                    _FIXTURES.append(p.read_bytes().decode("utf-8", errors="replace"))
            except OSError:
                continue
    return _FIXTURES


# ------------------------------------------------------------------------- regex vs regex

def _spans(pat, text):
    return [(m.span(), m.groups()) for m in pat.finditer(text)]


def _startfree(pat, text):
    return [(m.end(), m.groups(), [m.span(i) for i in range(1, pat.groups + 1)], m.group(0).strip())
            for m in pat.finditer(text)]


def _first(pat, text):
    m = pat.search(text)
    return None if m is None else (m.span(), m.groups())


_LABEL_RE = re.compile(r"[A-Za-z0-9-]+")


def _same(name, mode, old, new, text) -> "str | None":
    """None when *new* agrees with *old* on *text* under *mode*, else what differs."""
    if mode == "spans":
        return None if _spans(old, text) == _spans(new, text) else "spans"
    if mode == "startfree":
        return None if _startfree(old, text) == _startfree(new, text) else "ends/groups"
    if mode == "first":
        return None if _first(old, text) == _first(new, text) else "first match"
    if mode == "truth":
        if bool(old.search(text)) != bool(new.search(text)):
            return "truth value"
        o, n = _first(old, text), _first(new, text)
        if o != n:   # may only begin earlier, on leading ".+-" of the same run
            if not (o[0][1] == n[0][1] and n[0][0] <= o[0][0]
                    and set(text[n[0][0]:o[0][0]]) <= set(".+-")):
                return "more than a leading .+- shift"
        return None
    if mode == "urlsub":
        a = old.sub(lambda m: "<" + m.group(0) + ">", text)
        b = new.sub(lambda m: m.group(1) + "<" + m.group(2) + ">", text)
        return None if a == b else "substitution"
    if mode == "host63":
        if any(len(m.group(0)) > 63 for m in _LABEL_RE.finditer(text)):
            return None      # an over-long label: the documented difference, pinned separately
        return None if _spans(old, text) == _spans(new, text) else "spans"
    if mode == "jsbrace":
        o = _startfree(old, text)
        if o == _startfree(new, text):
            return None
        return None if any("{" in (g or "") for _e, gs, _s, _t in o for g in gs) else "name lists"
    if mode == "shrun":
        from clawseccheck import skillast
        a = [(m.start(), m.span("path"), m.group("path")) for m in old.finditer(text)]
        b, prev = [], 0
        for m in new.finditer(text):
            b.append((skillast._sh_run_stmt_start(text, m, prev), m.span("path"), m.group("path")))
            prev = m.end()
        return None if a == b else "statement start / path"
    raise AssertionError(mode)


@pytest.mark.parametrize("name", REGEX_PAIRS)
def test_rewritten_pattern_matches_what_the_old_one_did(name):
    old, new, mode = _old(name), _new(name), _mode(name)
    short = name.rsplit(".", 1)[-1]
    assert old.pattern != new.pattern, "the pattern text did not change - nothing to compare"
    assert old.flags == new.flags
    hits = 0
    for text in _strings(short, old.pattern, 4000):
        hits += bool(old.search(text))
        why = _same(name, mode, old, new, text)
        assert why is None, (name, why, text[:120])
    assert hits >= 25, f"{name}: only {hits} corpus strings match the old pattern"
    for text in _fixture_texts():
        why = _same(name, mode, old, new, text)
        assert why is None, (name, why, "fixture text", text[:80])


def test_every_changed_pattern_is_covered():
    """A pattern rewritten for C-730 that is in neither table would go unchecked."""
    assert len(REGEX_PAIRS) == len(set(REGEX_PAIRS)) == 27
    assert len(_fixture_texts()) > 500


def test_known_limit_dest_pattern_under_finditer():
    """The e-mail leg's tail class is narrower than its prefix class, so a match can end inside
    a run; the old pattern then tried again from there, the new one (lookbehind) does not. Every
    call site reads the FIRST match (`.search`), which is identical - this pins the limit so
    nobody starts calling `.finditer` on it."""
    name = "checks._content._B63_DEST_RE"
    old, new = _old(name), _new(name)
    text = "x@y.zz+q@r.ss"
    assert len(list(old.finditer(text))) == 2 and len(list(new.finditer(text))) == 1
    assert _first(old, text) == _first(new, text)


def test_known_limit_host_label_longer_than_a_dns_label():
    """A "subdomain" longer than 63 characters names no reachable host. It is no longer
    swallowed whole into the match: the bare-domain arms still convict `.ngrok.io`,
    `.ngrok-free.app` and `.pipedream.net`, and `.ngrok.app` / `.ngrok-free.io` are matched
    from the last word boundary within 63 characters of the dot, or not at all."""
    name = "checks._shared._KNOWN_EXFIL_HOST_RE"
    old, new = _old(name), _new(name)
    long = "a" * 70
    for host, expect in ((long + ".ngrok.io", "ngrok.io"), (long + ".ngrok-free.app", "ngrok-free.app"),
                         (long + ".pipedream.net", "pipedream.net"), (long + ".ngrok.app", None),
                         (long + ".ngrok-free.io", None),
                         ("a-" * 40 + "b.ngrok.app", "a-" * 31 + "b.ngrok.app")):
        assert old.search(host).group(0) == host
        got = new.search(host)
        assert (got.group(0) if got else None) == expect, host[-24:]
    edge = "a" * 63 + ".ngrok.app"
    assert new.search(edge).group(0) == old.search(edge).group(0) == edge


def test_known_difference_js_default_value_pattern():
    """`{ a: { b } = require('child_process') }`: the old text read "a: { b" as one name; the
    inner list is matched now and `b` - which is bound to the module - is the name."""
    name = "skillast._JS_CP_DESTRUCTURE_BIND_RE"
    text = "const { a: { b } = require('child_process') } = o"
    assert _old(name).search(text).group(1) == "a: { b"
    assert _new(name).search(text).group(1) == "b"


_QUADRATIC_UNIT = {
    "_B58_URL_OR_EMAIL_RE": "a.", "_B61_TOOL_DECL_RE": " ", "_B63_DEST_RE": "x", "_DEP_PKG_NAME_RE": " ",
    "_FM_HOMEPAGE_RE": "\n", "_PTH_IMPORT_LINE_RE": "\n", "_PYPROJECT_DEP_LINE_RE": "\n",
    "_REQ_UNPINNED_RE": " ", "_SYSTEMD_EXECSTART_RE": "\n", "_SYSTEMD_RESTART_RE": "\n",
    "_SYSTEMD_WANTEDBY_RE": "\n", "_KNOWN_EXFIL_HOST_RE": "a-", "_SECRET_PATH_RE": "x",
    "_F052_NONBREAK_RE": ".x", "_RUNTIME_FETCH_TABLE_DELIM_LINE_RE": " ", "_URL_SHAPE_RE": "x",
    "_SKILL_VERSION_RE": "\n", "_B164_NOT_SCANNED_RE": "0", "_B164_SQLITE_TRANSCRIPT_DB_RE": "0",
    "_B164_SQLITE_TRANSCRIPT_RE": "0", "_B164_SQLITE_UNSCANNED_RE": "0", "_TRACKER_CONNECTOR_RE": " ",
    "_JS_CP_DESTRUCTURE_BIND_RE": "{", "_SH_CASE_WILDCARD_ARM_RE": " ", "_SH_RUN_PATH_RE": "\n",
    "_SSH_R_SPEC_RE": ":", "_OPENCLAW_CRED_STORE_RE": "x",
}
# Used with `.match` at one position (the guard times them the same way).
_MATCH_ONLY = {"_RUNTIME_FETCH_TABLE_DELIM_LINE_RE", "_SH_CASE_WILDCARD_ARM_RE", "_SSH_R_SPEC_RE"}


def _best(fn, n=3):
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t0)
    return min(out)


@pytest.mark.parametrize("name", REGEX_PAIRS)
def test_new_pattern_is_much_faster_than_the_old_one_on_its_long_run(name):
    """Relative timing in one process: the old pattern re-scans the run from every start."""
    short = name.rsplit(".", 1)[-1]
    old, new, unit = _old(name), _new(name), _QUADRATIC_UNIT[short]
    text = unit * (6000 // len(unit))

    def run(pat):
        if short in _MATCH_ONLY:
            return lambda: pat.match(text)
        return lambda: list(pat.finditer(text))

    t_old = _best(run(old), 2)
    t_new = _best(run(new), 3)
    assert t_old > 8 * max(t_new, 1e-5), (name, t_old, t_new)


# ------------------------------------------------------------------- scanner vs reference

def _scanner_cases():
    from clawseccheck.checks import _content as c
    from clawseccheck.checks import _shared as s

    def tags(m):
        return (m.span(), m.group("tag"), m.group("attrs"), m.group("body"))

    return {
        "checks._content._B59_MD_LINK_RE": (
            c._b59_md_links, lambda m: (m.start(), m.group(1)), lambda t: t,
            ["[", "]", "(", ")", "!", "\n", "a", "b", " ", "x?y=1", "http://h/", "[a](u)", "![i](v)",
             "](", "[]", "()", "![", "![](z)", "!![", "\\"]),
        "checks._content._B59_MD_IMG_RE": (
            c._b59_md_images, lambda m: (m.start(), m.group(1)), lambda t: t,
            ["[", "]", "(", ")", "!", "\n", "a", "b", " ", "x?y=1", "http://h/", "[a](u)", "![i](v)",
             "](", "[]", "()", "![", "![](z)", "!![", "\\"]),
        "checks._content._B59_HTML_TAG_RE": (
            c._b59_html_tags, lambda m: (m.start(), m.group(0)), lambda m: (m.start(), m.group(0)),
            ["<", ">", "a", "img", "<a", "<img", "<A", "<IMG", " ", "\n", "href='x'", "b", "<ab", "<a>",
             "<img/>", "a>", "<a-b", "<a_", EACUTE, "<a" + EACUTE, "/", "="]),
        "checks._content._B58_HIDDEN_TAG_RE": (
            c._b58_hidden_tags, tags, tags,
            ["<", ">", "</", "a", "b", "ab", "A", "div", "span", " ", "\n", " style='display:none'",
             "x", "<a>", "</a>", "<ab>", "</ab>", "<div>", "</div>", "</A>", "<B>", ":", "-", "_", "1",
             "/", "<<", ">>", LONG_S, "s", KELVIN, "k", "<s>", "</" + LONG_S + ">", "<k>",
             "</" + KELVIN + ">", EACUTE, "<" + EACUTE + ">", DOTTED_I, "i", "<i>",
             "</" + DOTTED_I + ">", "<" + KELVIN + ">", "</k>", "</K>", "<S>", "</s>",
             "<" + LONG_S + ">"]),
        "checks._content._MODEL_FILE_URL_RE": (
            c._model_file_urls, lambda m: (m.span(), m.group(0)), lambda m: (m.span(), m.group(0)),
            ["http://", "https://", "HTTP://", "a", "b", "/", ".", ".gguf", ".GGUF", ".onnx",
             ".safetensors", ".ggufx", ".gguf_", " ", "\n", '"', "'", "<", ">", ")", "]", "?x=1", ",",
             ":", "x.gguf", "h/m.onnx", "-", EACUTE, "htt", "p://", "s://"]),
        "checks._shared._PB_TOK_RE": (
            s._pb_tok_matches, lambda m: (m.start(), m.end(), m.group(0)),
            lambda m: (m.start(), m.end(), m.group(0)),
            ["{", "}", "{{", "}}", "{{x}}", "{{ a }}", "$", "${V}", "$x", "<t>", "<", ">", "`", "`c`",
             "http://a/b", "https://x", "don't", "word", "U.S.", "a.com/x", chr(0x2014), chr(0x2013),
             "--", "-", ",", ";", ":", "(", ")", " ", "  ", "\n", "x", "1", "'", chr(0x2019), ".",
             "{{{", "}}}", EACUTE]),
    }


REFERENCES = sorted(n for n, p in PINS.items() if p["mode"] == "reference")


@pytest.mark.parametrize("name", REFERENCES)
def test_scanner_yields_exactly_the_reference_patterns_matches(name):
    scanner, sig_ref, sig_scan, alphabet = _scanner_cases()[name]
    ref = _new(name)
    pin = PINS[name]
    assert (ref.pattern, ref.flags) == (pin["pattern"], pin["flags"]), (
        f"{name} is the definition its scanner is tested against and must stay as it was")
    rnd = random.Random("c730:" + name)
    hits = 0
    for _ in range(40000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 16)))
        want = [sig_ref(m) for m in ref.finditer(text)]
        hits += bool(want)
        assert [sig_scan(m) for m in scanner(text)] == want, (name, text[:120])
    assert hits >= 2000, (name, hits)
    for text in _fixture_texts():
        assert [sig_scan(m) for m in scanner(text)] == [sig_ref(m) for m in ref.finditer(text)], (
            name, "fixture text", text[:80])


def test_hidden_tag_body_bound_is_the_patterns():
    from clawseccheck.checks import _content as c
    for gap, found in ((4095, True), (4096, True), (4097, False)):
        text = "<a>" + "x" * gap + "</a>"
        assert bool(c._B58_HIDDEN_TAG_RE.search(text)) is found
        assert bool(list(c._b58_hidden_tags(text))) is found


def test_strip_tags_is_the_old_substitution():
    from clawseccheck.checks import _content as c
    old = re.compile(r"<[^>]+>")
    rnd = random.Random("c730:strip")
    alphabet = ["<", ">", "a", " ", "\n", "<b>", "<>", "x", "<<", ">>", "/"]
    for _ in range(40000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 16)))
        assert c._b58_strip_tags(text) == old.sub(" ", text), text
    for text in _fixture_texts():
        assert c._b58_strip_tags(text) == old.sub(" ", text)


_INLINE = [
    # (source file, new pattern text as it appears there, old pattern text, how it is used)
    ("clawseccheck/skillast.py", r":\s*|(?<!\s)\s+as\s+", r":\s*|\s+as\s+", "split"),
    ("clawseccheck/checks/_shared.py", r"(?<![A-Za-z.])\.*([A-Za-z](?:[A-Za-z.]*[A-Za-z])?)\.$",
     r"([A-Za-z](?:[A-Za-z.]*[A-Za-z])?)\.$", "group1"),
]


@pytest.mark.parametrize("src,new,old,how", _INLINE, ids=["js-alias-split", "abbrev-before-period"])
def test_inline_rewrite_reads_the_same(src, new, old, how):
    assert (ROOT / src).read_text(encoding="utf-8").count('r"' + new + '"') == 1, "pattern not in source"
    r_new, r_old = re.compile(new), re.compile(old)
    rnd = random.Random("c730:" + src)
    alphabet = ["a", "b", "exec", "as", " as ", ": ", ":", " ", "  ", "\t", ".", "..", "x.", "U.S.",
                "e.g", "Z", "1", ",", "\n", "-"]
    hits = 0
    for _ in range(40000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 14)))
        if how == "split":
            assert r_new.split(text) == r_old.split(text), text
            hits += len(r_old.split(text)) > 1
        else:
            text = text.rstrip()
            a, b = r_old.search(text), r_new.search(text)
            assert (a.group(1) if a else None) == (b.group(1) if b else None), text
            hits += a is not None
    assert hits >= 2000


# ------------------------------------------------------------------- the scanners are linear

def _scanner_units():
    from clawseccheck.checks import _content as c
    from clawseccheck.checks import _shared as s
    return [
        (c._b59_md_links, ["[", "[a](x", "[a]", "](", "[[a]("]),
        (c._b59_md_images, ["![", "![a](x", "![a]", "!"]),
        (c._b59_html_tags, ["<a ", "<a", "<img x", "<a>"]),
        (c._b58_hidden_tags, ["<a ", "<a>", "<a <b >", "<ab>", "<a></", "<a>x</b>"]),
        (c._model_file_urls, ["http://", "http://a", ".gguf", "http://a.gguf,"]),
        (s._pb_tok_matches, ["{{ ", "{", "{{", "{{ }", "{{a} "]),
        (c._b58_strip_tags, ["<", "<a", "<>", "<a>"]),
    ]


def test_hidden_tags_is_linear_in_one_long_tag_name():
    """A single opening tag with a very long name, closed by a shorter prefix of it: the
    regex may settle for any prefix, so a per-prefix search would be quadratic in the name."""
    from clawseccheck.checks import _content as c

    def doc(n):
        return "<" + "a" * n + ">x</" + "a" * (n // 2) + ">"

    for n in (100, 3000):
        assert [(m.span(), m.group("tag")) for m in c._b58_hidden_tags(doc(n))] == [
            (m.span(), m.group("tag")) for m in c._B58_HIDDEN_TAG_RE.finditer(doc(n))]
    t1 = _best(lambda: list(c._b58_hidden_tags(doc(4000))))
    t2 = _best(lambda: list(c._b58_hidden_tags(doc(16000))), 2)
    assert t2 < 0.02 or t2 < 9 * t1, (t1, t2)


def test_known_difference_js_destructure_inside_a_block():
    name = "skillast._JS_CP_DESTRUCTURE_BIND_RE"
    text = 'function go() { const { exec } = require("child_process"); exec(cmd); }'
    assert _old(name).search(text).group(1) == "const { exec"
    assert _new(name).search(text).group(1) == "exec"


def test_scanners_are_linear_time():
    """4x the input must cost about 4x. Relative, in one process; a quadratic scanner costs 16x."""
    for fn, units in _scanner_units():
        for unit in units:
            small = unit * (20_000 // len(unit))
            big = unit * (80_000 // len(unit))

            def run(text):
                out = fn(text)
                return out if isinstance(out, (str, list)) else sum(1 for _ in out)

            t1 = _best(lambda: run(small))
            t2 = _best(lambda: run(big), 2)
            assert t2 < 0.02 or t2 < 9 * t1, (fn.__name__, unit, t1, t2)
