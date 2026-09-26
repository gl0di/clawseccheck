"""Guards for .gitleaks.toml / .gitleaksignore: exemptions are exact values, never places.

The old config exempted `fixtures/` and `tests/` wholesale (about 93% of tracked files)
plus a global stopword list, so a real-shaped secret pasted into a test was invisible to
the only mechanical enforcement of the no-secrets-in-source rule. These tests read the
config as TEXT (tomllib is 3.11+, the CI floor is 3.9) and pin the narrow shape.

B-841: the original `_allow_regexes()` understood exactly one shape --
`regexes = ['''...''']`, a single triple-single-quoted entry per list. A double-quoted
list (`regexes = [".*"]`), a multi-entry list (`regexes = ['''a''', '''b''']`), or scope
broadened through `paths` / `stopwords` / `commits` / `regexTarget` / `condition` all
slipped past every test in this module untouched -- an adversarial review of B-828 could
append any of them and watch all seven tests stay green. The parsing below understands
the actual grammar (both quote styles, any number of entries) and a fixed vocabulary of
scope-broadening keys, and fails loudly on anything it doesn't recognize instead of
silently contributing nothing. `test_guard_catches_known_bypass_shapes` mutates a copy of
the real config text with each reported bypass and proves the guard now rejects it.

C-575: one more shape the B-841 pass missed -- a GLOBAL allowlist written as an inline
table, `allowlist = { paths = [...] }`, instead of a `[allowlist]` header line. It binds
to the same root `Config.Allowlist` field (confirmed against gitleaks 8.24.3 with a
scratch secret and a scratch config: present, `leaks found: 1`; with the inline table
prepended before `[extend]`, `no leaks found`) but the old header-only check and the
line-anchored `paths` check both miss it, because there is no `[allowlist]` line and
`paths` sits mid-line inside `{ ... }`, not at line start. See
`_FORBIDDEN_BARE_ALLOWLIST_RE` and `test_guard_catches_top_level_inline_allowlist_bypass`.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONFIG = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
IGNORE = (ROOT / ".gitleaksignore").read_text(encoding="utf-8")
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

_PINNED_FINGERPRINTS = {
    "8f274c2879548fc42fa0f0293238c8be71c11e10:fixtures/clean_b13_hardcoded_plain_assignment_comment/skills/s/runner.py:stripe-access-token:7",
    "8f274c2879548fc42fa0f0293238c8be71c11e10:fixtures/clean_b13_hardcoded_plain_assignment_comment/skills/s/runner.py:stripe-access-token:12",
    "8f274c2879548fc42fa0f0293238c8be71c11e10:tests/test_b740_plain_assignment_secret.py:stripe-access-token:128",
    "8f274c2879548fc42fa0f0293238c8be71c11e10:tests/test_b740_plain_assignment_secret.py:stripe-access-token:141",
    "24995977c5e45bf0221ad56348cc28b79da12fd2:tests/test_logsafe.py:gcp-api-key:58",
    "24995977c5e45bf0221ad56348cc28b79da12fd2:tests/test_logsafe.py:gcp-api-key:60",
    # C-575 split four dummy literals into runtime-assembled fragments at HEAD and dropped
    # their value-anchored `generic-api-key` allowlist entries. The values remain in the
    # commits that introduced them and published history is never rewritten, so each
    # occurrence is pinned to its own commit here -- narrower than the allowlist it
    # replaced, which exempted the value everywhere including in new code.
    "0e23b8f7cec69e80d91e24f7f2017e2a4dab0630:tests/test_logscan.py:generic-api-key:993",
    "d5daee01d3fe9d28bf57d713dc52695f0d7b1f7d:tests/test_logscan.py:generic-api-key:96",
    "7d75cba4b8bddf11e1d3d45e962228356e6f84aa:tests/test_checks.py:generic-api-key:61",
    "7d75cba4b8bddf11e1d3d45e962228356e6f84aa:tests/test_windows.py:generic-api-key:23",
    # Two non-secret test inputs published on dev before the 4.3.0 release scan caught
    # them (a "sk-REPLACE_ME-…" placeholder default and a bearer header whose value is
    # the shell variable $f); both are split into fragments at HEAD.
    "47fb954d43148120217c6373353be1e868da1542:tests/test_b997_placeholder_patterns.py:generic-api-key:91",
    "234c5577f980a73ac772a509221b6fa99caac6c3:tests/test_b894_shell_loop_cred_taint.py:curl-auth-header:720",
}

# gitleaks allowlist keys that broaden an exemption beyond one exact, anchored value:
# a file path, a whole commit, a stopword list, matching the entire line instead of just
# the value, or an AND/OR combinator. None of them is ever legitimate in this file.
_FORBIDDEN_SCOPE_KEYS = ("paths", "stopwords", "commits", "regexTarget", "condition")
_EXPECTED_REGEX_COUNT = 4

# C-575: gitleaks's own Config struct binds its GLOBAL allowlist to the singular TOML key
# `allowlist` (per-rule exemptions use the plural array `[[rules.allowlists]]`, which this
# file uses throughout and which stays legitimate). A root-level `allowlist = { ... }` --
# TOML's inline-table form of a `[allowlist]` header, so no `[allowlist]` line ever appears
# for a reviewer or the old header-only check to see -- reinstates the exact repo-wide
# `paths = [...]` exemption B-828 removed. Measured against the pinned gitleaks 8.24.3: a
# `clh_`-shaped probe in a scratch file scans as `leaks found: 1` against this config
# unmodified, and `no leaks found` once `allowlist = { paths = ["<that file>"] }` is
# prepended before `[extend]`. Position is load-bearing and was checked, not assumed: TOML
# scopes bare keys to the nearest preceding table header, so the same line inserted right
# after `[extend]`'s `useDefault = true` -- still inside the `[extend]` table -- measured as
# an inert no-op (`leaks found: 1`, unchanged) rather than a working bypass; only a
# pre-`[extend]` (root-scope) placement suppressed the finding. The line-anchored key checks
# above never saw this: `paths` here sits mid-line after `allowlist = {`, not at line start.
_FORBIDDEN_BARE_ALLOWLIST_RE = re.compile(r"\ballowlist\b\s*=", re.I)
# C-575, optional item: the three tests/*.py exact-value exemptions (test_logscan.py x2,
# test_checks.py x1) were dropped after their dummy literals were split into fragments at
# the source, per CLAUDE.md golden rule 3 -- 7 - 3 = 4 remaining (3 fixtures/ + 1
# corpus.json), none of them ours to fix (base64-in-fixture and third-party-shaped corpus
# data, not a plain contiguous literal we authored).


def _strip_comments(text):
    return "\n".join(re.sub(r"^\s*#.*$", "", ln) for ln in text.splitlines())


CODE = _strip_comments(CONFIG)


def _find_bracket_span(text, start):
    """Return `(content, end)` for the `[ ... ]` array whose `[` is at `text[start]`.

    Walks the array by hand instead of with one regex so a `]` or `,` inside a quoted
    string can't be mistaken for the array's own delimiters.
    """
    assert text[start] == "[", text[start:start + 20]
    i, n = start + 1, len(text)
    while i < n:
        c = text[i]
        if c == "]":
            return text[start + 1:i], i + 1
        if text.startswith("'''", i):
            end = text.find("'''", i + 3)
            assert end != -1, f"unterminated ''' inside list: {text[start:start + 80]!r}"
            i = end + 3
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            assert j < n, f"unterminated \" inside list: {text[start:start + 80]!r}"
            i = j + 1
            continue
        i += 1
    raise AssertionError(f"unterminated [ ... ] list: {text[start:start + 80]!r}")


def _parse_string_list(content):
    """Parse comma-separated string literals -- `'''...'''` or `"..."` -- out of the
    inside of a `[ ... ]` array. Raises on any other token (a bare identifier, a
    number, string concatenation, ...) so an unrecognized shape fails loudly instead
    of silently contributing zero entries.
    """
    items = []
    i, n = 0, len(content)
    while i < n:
        c = content[i]
        if c in " \t\r\n,":
            i += 1
            continue
        if content.startswith("'''", i):
            end = content.find("'''", i + 3)
            assert end != -1, f"unterminated ''' string: {content!r}"
            items.append(content[i + 3:end])
            i = end + 3
            continue
        if c == '"':
            j = i + 1
            buf = []
            while j < n and content[j] != '"':
                if content[j] == "\\":
                    assert j + 1 < n and content[j + 1] in ('"', "\\"), (
                        f"unsupported escape in: {content!r}"
                    )
                    buf.append(content[j + 1])
                    j += 2
                    continue
                buf.append(content[j])
                j += 1
            assert j < n, f"unterminated \" string: {content!r}"
            items.append("".join(buf))
            i = j + 1
            continue
        raise AssertionError(f"unrecognized token {content[i:i + 20]!r} in list: {content!r}")
    return items


def _allow_regexes(code=None):
    """Every individual regex string inside every `regexes = [...]` list in `code`
    (the real config by default). Understands both TOML string-quoting styles
    gitleaks accepts and both single- and multi-entry lists -- unlike the original
    version this replaces, which only matched a single `'''...'''` entry.
    """
    if code is None:
        code = CODE
    regexes = []
    for m in re.finditer(r"\bregexes\s*=\s*(\[)", code, re.I):
        content, _end = _find_bracket_span(code, m.start(1))
        items = _parse_string_list(content)
        assert items, f"empty regexes list: {m.group(0)!r}"
        regexes.extend(items)
    return regexes


def _forbidden_scope_keys(code=None):
    """Any key or table this config must never contain -- see `_FORBIDDEN_SCOPE_KEYS`.

    Matched case-INSENSITIVELY, and that is load-bearing rather than defensive. gitleaks
    decodes this file into Go structs whose fields are `Paths`, `Regexes`, `StopWords`,
    `Commits`, `RegexTarget`; BurntSushi/toml binds a TOML key to a struct field by a
    case-insensitive fallback when no explicit tag names it, which is exactly why the
    config's own lowercase `regexes` works against the Go field `Regexes` today.

    So a capitalised spelling is honoured by the real scanner while a case-SENSITIVE guard
    sees nothing. Measured on the pinned gitleaks 8.24.3 against a `clh_`-shaped value:
    the stock config reports `leaks found: 1`, and appending an allowlist whose key is
    spelled `Paths` (capital P) reports `no leaks found` -- while `_forbidden_scope_keys`
    returned `[]` for that same text. A one-character change, indistinguishable from a typo
    in review, silently disabled the scanner and left every test in this file green. Do not
    "tidy" these flags away.
    """
    if code is None:
        code = CODE
    hits = [key for key in _FORBIDDEN_SCOPE_KEYS
            if re.search(rf"^\s*{key}\s*=", code, re.M | re.I)]
    if re.search(r"^\s*\[allowlist\]", code, re.M | re.I):
        hits.append("[allowlist]")
    if re.search(r"^\s*\[\[allowlists\]\]", code, re.M | re.I):
        hits.append("[[allowlists]]")
    if _FORBIDDEN_BARE_ALLOWLIST_RE.search(code):
        hits.append("allowlist=")
    return hits


def _rule_blocks():
    """Split CODE into top-level [[rules]] blocks, excluding nested [[rules.allowlists]] tables."""
    parts = re.split(r"(?m)^\[\[rules\]\]\s*$", CODE)
    return parts[1:]  # drop the preamble before the first [[rules]]


def _rule_ids():
    """The declared id of each top-level [[rules]] block, in file order (dupes kept, not deduped)."""
    ids = []
    for block in _rule_blocks():
        # id must be declared on the rule itself, before any nested [[rules.xxx]] table
        head = re.split(r"(?m)^\[\[rules\.", block)[0]
        m = re.search(r'^\s*id\s*=\s*"([^"]+)"\s*$', head, re.M)
        if m:
            ids.append(m.group(1))
    return ids


def _tok(prefix, n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    return prefix + (alphabet * 3)[:n]


_PROBES = (
    _tok("gh" + "p_", 36),
    _tok("AK" + "IA", 16, "ABCDEFGHIJKLMNOP"),
    _tok("cl" + "h_", 40),
    _tok("s" + "k-", 48),
    _tok("sk_" + "live_", 24),
    _tok("AI" + "za", 35),
)


def _assert_exemptions_are_exact(code):
    """The full guard, parameterized on config text so both the real file and the
    bypass mutations below run through the exact same checks."""
    hits = _forbidden_scope_keys(code)
    assert not hits, hits
    for rx in _allow_regexes(code):
        assert rx.startswith("^") and rx.endswith("$"), rx
        assert ".*" not in rx and ".+" not in rx and "|" not in rx, rx
        for p in _PROBES:
            assert not re.search(rx, p), (rx, p[:6])


def test_no_path_or_global_stopword_exemption():
    assert _forbidden_scope_keys() == []


def test_default_rules_still_extended():
    assert re.search(r"^useDefault\s*=\s*true\s*$", CODE, re.M)


def test_exemptions_are_anchored_exact_values():
    regexes = _allow_regexes()
    assert len(regexes) == _EXPECTED_REGEX_COUNT
    _assert_exemptions_are_exact(CODE)


def test_exemptions_do_not_match_real_shaped_tokens():
    for rx in _allow_regexes():
        for p in _PROBES:
            assert not re.search(rx, p), (rx, p[:6])


def test_clawhub_rule_matches_token_not_placeholder():
    m = re.search(r"id = \"clawhub-cli-token\".*?regex = '''(.*?)'''", CODE, re.S)
    assert m
    rx = m.group(1)
    assert re.search(rx, "token " + _tok("cl" + "h_", 40))
    assert not re.search(rx, "clh_... placeholder")
    assert 'keywords = ["clh_"]' in CODE


def test_ignore_file_is_exactly_the_pinned_history_fingerprints():
    lines = [ln for ln in IGNORE.splitlines() if ln.strip() and not ln.startswith("#")]
    for ln in lines:
        assert re.fullmatch(r"[0-9a-f]{40}:[^:\s]+:[a-z0-9-]+:\d+", ln), ln
    assert set(lines) == _PINNED_FINGERPRINTS
    assert len(lines) == len(set(lines))


def test_ci_secret_scan_uses_this_config():
    assert "--config=.gitleaks.toml" in CI


# --- B-841: each of these, appended to a scratch copy of the real config, was
# reported to leave all seven tests above green under the original `_allow_regexes()`
# / forbidden-key check. `_assert_exemptions_are_exact` must now reject every one.

_BYPASS_DOUBLE_QUOTED_BLANKET = """
[[rules.allowlists]]
description = "scratch bypass: double-quoted blanket regex"
regexes = [".*"]
"""

_BYPASS_MULTI_ENTRY_LIST = """
[[rules.allowlists]]
description = "scratch bypass: a second, unanchored entry riding a valid one"
regexes = [
  '''^ok-value$''',
  '''.*''',
]
"""

_BYPASS_REGEX_TARGET_LINE = """
[[rules.allowlists]]
description = "scratch bypass: match the whole line, not just the value"
regexTarget = "line"
"""

_BYPASS_COMMITS = """
[[rules.allowlists]]
description = "scratch bypass: exempt an entire commit instead of one value"
commits = ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
"""

# gitleaks decodes this file into Go structs (`Paths`, `Regexes`, `StopWords`, ...) and
# BurntSushi/toml binds a key to a field case-insensitively when no tag names it -- which
# is why the lowercase spellings above work at all. So a capitalised key is honoured by the
# real scanner. Measured on the pinned gitleaks 8.24.3 with a `clh_`-shaped value: the stock
# config reports `leaks found: 1`; appending the `Paths` block below reports `no leaks
# found`. Before this was fixed the guard matched case-SENSITIVELY and returned nothing for
# either, leaving every test in this file green while the scanner was disabled.

_BYPASS_CAPITALISED_PATHS = """
[[rules.allowlists]]
description = "scratch bypass: path exemption spelled to dodge a case-sensitive guard"
Paths = ['''somepath/leak\\.py''']
"""

_BYPASS_CAPITALISED_REGEXES = """
[[rules.allowlists]]
description = "scratch bypass: blanket regex spelled to dodge a case-sensitive guard"
Regexes = ['''.*''']
"""

_BYPASS_CAPITALISED_STOPWORDS = """
[[rules.allowlists]]
description = "scratch bypass: stopword exemption spelled to dodge a case-sensitive guard"
StopWords = ["AKIA"]
"""


@pytest.mark.parametrize(
    "bypass",
    [
        _BYPASS_DOUBLE_QUOTED_BLANKET,
        _BYPASS_MULTI_ENTRY_LIST,
        _BYPASS_REGEX_TARGET_LINE,
        _BYPASS_COMMITS,
        _BYPASS_CAPITALISED_PATHS,
        _BYPASS_CAPITALISED_REGEXES,
        _BYPASS_CAPITALISED_STOPWORDS,
    ],
    ids=["double_quoted_blanket", "multi_entry_list", "regex_target_line", "commits_scope",
         "capitalised_paths", "capitalised_regexes", "capitalised_stopwords"],
)
def test_guard_catches_known_bypass_shapes(bypass):
    mutated = CODE + bypass
    with pytest.raises(AssertionError):
        _assert_exemptions_are_exact(mutated)


# C-575: a root-scope global allowlist written as an inline table instead of a
# `[allowlist]` header. Unlike the bypasses above, this one is PREPENDED, not appended --
# see `_FORBIDDEN_BARE_ALLOWLIST_RE`'s comment: gitleaks (measured on 8.24.3) only binds a
# bare top-level key to the root Config before any `[table]` header opens, so an appended
# copy would land inside the last-open table and do nothing. The guard's own check is a
# flat text search with no position sense, so it must reject this shape wherever it
# appears -- prepending here just keeps the test faithful to the one placement that is a
# real, working bypass against the actual scanner, rather than a purely textual exercise.
_BYPASS_TOP_LEVEL_INLINE_ALLOWLIST = (
    'allowlist = { paths = ["scratch-bypass-target.py"] }\n\n'
)


def test_guard_catches_top_level_inline_allowlist_bypass():
    mutated = _BYPASS_TOP_LEVEL_INLINE_ALLOWLIST + CODE
    with pytest.raises(AssertionError):
        _assert_exemptions_are_exact(mutated)


def test_guard_accepts_the_real_config_unmutated():
    # A sanity check that the mutation tests above exercise the guard logic itself
    # and not some incidental text search that would also reject well-formed input.
    _assert_exemptions_are_exact(CODE)


def test_no_duplicate_rule_ids():
    """CLAWSECCHECK-B-882: gitleaks resolves a repeated `[[rules]] id = "..."` as "last one
    wins" — verified end-to-end against the pinned 8.24.3 binary — with no warning or error
    either way, so a later block silently replaces an earlier rule's real regex/allowlist. A
    duplicate id is always a config bug (a rename that forgot to remove the old block, or a
    copy-paste), never an intentional shape, so it must fail loud here instead of quietly
    turning off detection.
    """
    ids = _rule_ids()
    assert ids, "expected at least one [[rules]] block in .gitleaks.toml"
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate [[rules]] id(s) in .gitleaks.toml (later block silently shadows the earlier one): {dupes}"


def test_duplicate_rule_ids_are_actually_detected():
    """Positive control for test_no_duplicate_rule_ids: prove the id-extraction/dup-check
    logic itself would fail on a real duplicate, not just pass vacuously on today's config.
    """
    synthetic = _strip_comments("""
[[rules]]
id = "example-rule"
regex = '''foo'''

[[rules]]
id = "generic-api-key"

[[rules.allowlists]]
regexes = ['''^placeholder$''']

[[rules]]
id = "example-rule"
regex = '''bar'''
""")
    parts = re.split(r"(?m)^\[\[rules\]\]\s*$", synthetic)[1:]
    ids = []
    for block in parts:
        head = re.split(r"(?m)^\[\[rules\.", block)[0]
        m = re.search(r'^\s*id\s*=\s*"([^"]+)"\s*$', head, re.M)
        if m:
            ids.append(m.group(1))
    assert ids == ["example-rule", "generic-api-key", "example-rule"]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert dupes == ["example-rule"]
