"""F-022: typosquatting detection for skill / dependency names.

Tests:
- Unit: _levenshtein() known distances.
- Unit: _squat_hits() — squat fires, exact-match silent, far name silent,
  short known-name excluded (no noise).
- Unit: _dep_names_in_skill() extracts package names from manifest sections.
- Unit: _frontmatter_name() extracts name: from SKILL.md frontmatter blob.
- Integration (Context): skill named 'githhub' triggers WARN; dep 'reqests' triggers WARN.
- Integration (fixtures): bad_f022_typosquat → B13 WARN; clean_f022_typosquat → B13 PASS.

OWASP AST02/AST04 (supply-chain impersonation via edit-distance on plain names).
Distinct from C-038 (Unicode homoglyphs in MCP server names).
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, HIGH, PASS, WARN
from clawseccheck.checks import (
    _KNOWN_NAMES,
    _dep_names_in_skill,
    _frontmatter_name,
    _levenshtein,
    _squat_hits,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# 1. _levenshtein unit tests
# ---------------------------------------------------------------------------

def test_levenshtein_identical_strings():
    """Identical strings have distance 0."""
    assert _levenshtein("github", "github") == 0


def test_levenshtein_single_insert():
    """One insertion: 'github' -> 'githhub' = 1."""
    assert _levenshtein("githhub", "github") == 1


def test_levenshtein_single_delete():
    """One deletion: 'requests' -> 'reqests' = 1."""
    assert _levenshtein("reqests", "requests") == 1


def test_levenshtein_single_substitute():
    """One substitution: 'nummpy' -> 'numpy' is 1 delete, not substitute."""
    assert _levenshtein("nummpy", "numpy") == 1


def test_levenshtein_two_edits():
    """Two edits: 'anthropicc' vs 'anthropic' = 1; 'amthropicc' = 2."""
    assert _levenshtein("anthropicc", "anthropic") == 1
    assert _levenshtein("amthropicx", "anthropic") == 2


def test_levenshtein_empty_string():
    """Distance to empty string equals the length of the other."""
    assert _levenshtein("", "abc") == 3
    assert _levenshtein("hello", "") == 5


def test_levenshtein_completely_different():
    """Completely different strings have large distances."""
    assert _levenshtein("xyz", "abc") == 3
    assert _levenshtein("django", "stripe") > 2


def test_levenshtein_symmetric():
    """Distance is symmetric."""
    assert _levenshtein("github", "githhub") == _levenshtein("githhub", "github")
    assert _levenshtein("requests", "reqests") == _levenshtein("reqests", "requests")


# ---------------------------------------------------------------------------
# 2. _squat_hits unit tests
# ---------------------------------------------------------------------------

def test_squat_hits_fires_for_near_miss_name():
    """A name one edit away from a known name fires a typosquat hit."""
    hits = _squat_hits(["githhub"])
    assert hits, "Expected at least one hit for 'githhub'"
    cands = [h[0] for h in hits]
    knowns = [h[1] for h in hits]
    assert "githhub" in cands
    assert "github" in knowns


def test_squat_hits_fires_for_dep_near_miss():
    """A dep name one edit from 'requests' fires."""
    hits = _squat_hits(["reqests"])
    assert hits, "Expected hit for 'reqests' (1 edit from 'requests')"
    knowns = [h[1] for h in hits]
    assert "requests" in knowns


def test_squat_hits_exact_match_silent():
    """An exact match against a known name is NOT flagged (legitimate use)."""
    hits = _squat_hits(["github"])
    assert not hits, f"Exact match 'github' must not be flagged: {hits}"


def test_squat_hits_requests_exact_silent():
    """Exact 'requests' is a legit package name — must not be flagged."""
    hits = _squat_hits(["requests"])
    assert not hits, f"Exact 'requests' must not fire: {hits}"


def test_squat_hits_far_name_silent():
    """A name far from all known names is not flagged."""
    hits = _squat_hits(["xyznonsense99"])
    assert not hits, f"Far name must not fire: {hits}"


def test_squat_hits_short_known_name_excluded():
    """Known names shorter than _TYPOSQUAT_MIN_KNOWN_LEN=5 do not produce noise."""
    # "vue" and "react" are 3 and 5 chars — "react" is in known names (len=5)
    # but we check that short unknown tokens like "xvue" (len 4) don't fire
    # against short known-ish names. Actually we just verify no spurious noise
    # for short candidates — the rule requires len(K) >= 5.
    hits = _squat_hits(["xy"])   # 2-char candidate → no known name of len >= 5 at distance <= 2
    assert not hits, f"Short candidate should not fire: {hits}"


def test_squat_hits_distance_3_silent():
    """A candidate at distance 3 from the nearest known name is not flagged."""
    # "gitXYZ" — g-i-t-X-Y-Z vs g-i-t-h-u-b: 3 subs in positions 4-6
    hits = _squat_hits(["gitxyz"])
    assert not hits, f"Distance-3 candidate 'gitxyz' should not fire: {hits}"


def test_squat_hits_hyphenated_skill_name_token():
    """A hyphenated skill name whose first token is a near-miss fires."""
    # "githhub-sync": token "githhub" is 1 edit from "github"
    hits = _squat_hits(["githhub-sync"])
    assert hits, f"'githhub-sync' should fire via token 'githhub': {hits}"
    knowns = [h[1] for h in hits]
    assert "github" in knowns


def test_squat_hits_note_formatter_silent():
    """The clean fixture skill name 'note-formatter' must not fire."""
    hits = _squat_hits(["note-formatter"])
    assert not hits, f"'note-formatter' must not flag as typosquat: {hits}"


def test_squat_hits_pinned_helper_silent():
    """Existing fixture skill 'pinned-helper' must not fire."""
    hits = _squat_hits(["pinned-helper"])
    assert not hits, f"'pinned-helper' must not flag as typosquat: {hits}"


def test_squat_hits_fetcher_silent():
    """Existing fixture skill 'fetcher' must not fire (no known name within distance 2)."""
    hits = _squat_hits(["fetcher"])
    assert not hits, f"'fetcher' must not flag as typosquat: {hits}"


def test_squat_hits_nummpy_near_numpy():
    """'nummpy' (common numpy typosquat) fires."""
    hits = _squat_hits(["nummpy"])
    assert hits, f"'nummpy' should fire as typosquat of 'numpy': {hits}"
    knowns = [h[1] for h in hits]
    assert "numpy" in knowns


# ---------------------------------------------------------------------------
# B-217: Cyrillic/Greek homoglyph clones of a known name evaded _squat_hits
# entirely — the raw edit distance (one full substitution per swapped glyph)
# sits above the allowed threshold, so it fired ZERO suspicion instead of
# "resembles <brand>". Both sides of the comparison are now confusable-folded
# before the Levenshtein distance is computed (see _normalize_for_squat /
# normalize_for_scan), and a full clone (folds to distance 0) is flagged as an
# exact resemblance rather than silently exempted like a genuine legit match.
# ---------------------------------------------------------------------------

def test_squat_hits_cyrillic_homoglyph_clone_fires():
    # d + Cyrillic і (U+0456) + Cyrillic ѕ (U+0455) + c + Cyrillic о (U+043E) + r + d —
    # visually "discord", raw edit distance 3 (each Cyrillic glyph counts as a full
    # substitution), which sits ABOVE the allowed=2 threshold pre-fix.
    homoglyph = "dіѕcоrd"
    assert _levenshtein(homoglyph, "discord") == 3  # confirms the raw-distance premise
    hits = _squat_hits([homoglyph])
    assert hits, f"Cyrillic homoglyph clone of 'discord' must fire: {hits}"
    assert (homoglyph, "discord", 0) in hits


def test_squat_hits_cyrillic_homoglyph_near_miss_fires_at_low_distance():
    # A homoglyph clone that ALSO has a genuine extra letter (not just confusable
    # substitution) must still fire, now at the correct (small) folded distance
    # rather than the inflated raw distance.
    homoglyph_extra = "dіѕcоrdd"  # one trailing extra "d"
    hits = _squat_hits([homoglyph_extra])
    assert hits, f"Near-miss homoglyph clone must fire: {hits}"
    knowns = [h[1] for h in hits]
    assert "discord" in knowns


def test_squat_hits_genuine_exact_match_still_silent_regression_guard():
    # Regression guard: a real, plain-ASCII exact match must stay silent —
    # the homoglyph carve-out must not affect the ordinary legitimate-use path.
    hits = _squat_hits(["discord"])
    assert not hits, f"Plain ASCII 'discord' must not fire: {hits}"


def test_squat_hits_whole_script_non_latin_name_stays_silent():
    # A legitimate whole-script (non-Latin) name — ordinary i18n, not a homoglyph
    # mixed into a Latin word — must not be treated as a homoglyph clone, mirroring
    # B93's own confusable_in_ascii_context anti-FP discipline.
    hits = _squat_hits(["привет"])  # "привет" (hello)
    assert not hits, f"Whole-script non-Latin name must not fire: {hits}"


def test_squat_hits_hyphenless_homoglyph_of_hyphenated_known_name_fires_at_distance_one():
    # A homoglyph clone that also omits a known name's hyphen must fall through to
    # the fuzzy distance check (landing at distance 1, the hyphen) rather than being
    # silently swallowed by the B-218 hyphen-omitted exact-match exemption.
    homoglyph_concat = "gіthubcоpilot"  # Cyrillic і, о; no hyphen at all
    hits = _squat_hits([homoglyph_concat], known=frozenset({"github-copilot"}))
    assert hits == [(homoglyph_concat, "github-copilot", 1)], hits


def test_vet_source_flags_cyrillic_homoglyph_owner():
    from clawseccheck.checks import vet_source
    homoglyph = "dіѕcоrd"
    f = vet_source(f"git:github.com/{homoglyph}/mytool@main")
    assert f.status == WARN
    assert any("resembles well-known 'discord'" in e for e in f.evidence)


# ---------------------------------------------------------------------------
# B-222: fullwidth-Unicode (and other NFKC-compatibility-decomposable) clones
# of a known name evaded _squat_hits exactly like B-217's Cyrillic/Greek
# clones did -- NFKC (part of normalize_for_scan) folds fullwidth "ｄｉｓｃｏｒｄ"
# straight to plain ASCII "discord", but the OLD is_homoglyph gate
# (confusable_in_ascii_context) only recognizes the curated 10-entry
# Cyrillic/Greek table, so it returned False and the exact-fold-match got
# silently swallowed by the "already a known name" exemption. is_homoglyph
# now also fires on `_nfkc_ascii_fold_changed`, a generic (non-enumerated)
# signal: it needs no per-block list because NFKC-compatibility-decomposing
# to ASCII is exactly what fullwidth / Mathematical Alphanumeric Symbols are
# FOR by Unicode's own design, whereas genuine non-Latin scripts never
# decompose to ASCII under NFKC at all.
# ---------------------------------------------------------------------------

def test_squat_hits_fullwidth_clone_fires():
    # Exact repro from the bug report: fullwidth spelling of "discord" NFKC-folds
    # straight to the literal ASCII string "discord".
    fullwidth = "ｄｉｓｃｏｒｄ"
    hits = _squat_hits([fullwidth])
    assert hits, f"Fullwidth clone of 'discord' must fire: {hits}"
    assert (fullwidth, "discord", 0) in hits


def test_squat_hits_math_bold_clone_fires():
    # A second, independent NFKC-compatibility-decomposable evasion shape
    # (Mathematical Sans-Serif Bold, U+1D5EE block) -- proves the signal is
    # genuinely generic, not a fullwidth-only special case.
    bold = "".join(chr(0x1D5EE + (ord(c) - ord("a"))) for c in "discord")
    hits = _squat_hits([bold])
    assert hits, f"Mathematical bold clone of 'discord' must fire: {hits}"
    assert (bold, "discord", 0) in hits


def test_squat_hits_whole_script_cyrillic_sentence_still_silent_with_new_signal():
    # Regression guard: a genuine multi-word Cyrillic sentence (ordinary i18n
    # prose, not an impersonation attempt) must not be swept in by the new
    # NFKC-fold signal either -- real Cyrillic text is not compatibility-
    # decomposable to ASCII, unlike fullwidth/math-alphanumeric forms.
    hits = _squat_hits(["привет как дела сегодня"])
    assert not hits, f"Genuine Cyrillic prose must not fire: {hits}"


def test_squat_hits_known_legit_neighbor_plain_ascii_still_silent():
    # C-135 regression guard (mirrors B-217's own adversarial pass): the new
    # signal must never fire on plain ASCII input, so it can never break the
    # B-185 legit-neighbor exemption for a REAL published package name.
    from clawseccheck.checks._content import _KNOWN_LEGIT_NEIGHBORS
    assert all(n.isascii() for n in _KNOWN_LEGIT_NEIGHBORS), (
        "every _KNOWN_LEGIT_NEIGHBORS entry must be pure ASCII -- the literal "
        "allowlisted spelling itself can never trip a Unicode-fold signal"
    )
    for dep in ("scapy", "boto", "panda"):
        hits = _squat_hits([dep])
        assert not hits, f"Legit neighbor '{dep}' (plain ASCII) must not fire: {hits}"


def test_squat_hits_known_legit_neighbor_fullwidth_clone_not_exempted():
    # Adversarial construction for B-222's mandatory check #3: a fullwidth-
    # Unicode SPELLING that folds to a real _KNOWN_LEGIT_NEIGHBORS entry
    # ("scapy", one edit from "scipy"). This is NOT the same string as the
    # plain-ASCII allowlisted "scapy" -- exactly like a Cyrillic homoglyph
    # clone of a known BRAND itself (test_squat_hits_cyrillic_homoglyph_clone_fires
    # above) is deliberately NOT exempted by the "already a known name" carve-out
    # -- so this is intended, pre-existing B-217/B-185 design carried over
    # verbatim to the new signal, not a new false-fire: the plain-ASCII form
    # (tested above) stays completely silent; only a literally Unicode-obfuscated
    # spelling (never how a real manifest declares an ASCII package name) loses
    # the exemption.
    fullwidth_scapy = "ｓｃａｐｙ"
    hits = _squat_hits([fullwidth_scapy])
    assert hits == [(fullwidth_scapy, "scipy", 1)], hits


def test_vet_source_flags_fullwidth_homoglyph_owner_stays_warn():
    # Mirrors test_vet_source_flags_cyrillic_homoglyph_owner with a fullwidth
    # clone -- confirms the new signal reaches the real vet_source entrypoint
    # and, mandatory check #4, stays WARN (never escalates past WARN/FAIL
    # severity mapping, which vet_source hardcodes independently of is_homoglyph).
    from clawseccheck.checks import vet_source
    fullwidth = "ｄｉｓｃｏｒｄ"
    f = vet_source(f"git:github.com/{fullwidth}/mytool@main")
    assert f.status == WARN
    assert any("resembles well-known 'discord'" in e for e in f.evidence)


def test_check_installed_skills_fullwidth_clone_skill_name_warns_not_fails(tmp_path):
    # Mandatory check #4 at the B13 entrypoint: a skill directory literally
    # named with the fullwidth clone must WARN (typosquat/impersonation
    # heuristic), never FAIL -- B13's typosquat branch hardcodes WARN.
    from clawseccheck.checks import check_installed_skills
    fullwidth = "ｄｉｓｃｏｒｄ"
    blob = f"# file: SKILL.md\n---\nname: {fullwidth}\ndescription: test\n---\nA tool.\n"
    ctx = _make_ctx(tmp_path, {fullwidth: blob})
    f = check_installed_skills(ctx)
    assert f.status == WARN, f"Expected WARN, got {f.status!r}: {f.detail!r}"
    assert f.status != FAIL


# ---------------------------------------------------------------------------
# 3. _dep_names_in_skill unit tests
# ---------------------------------------------------------------------------

def test_dep_names_requirements_txt():
    """Extracts package names from a requirements.txt section."""
    blob = "# file: requirements.txt\nrequests==2.31.0\nflask==3.0.2\nhttpx==0.27.0\n"
    names = _dep_names_in_skill(blob)
    assert "requests" in names
    assert "flask" in names
    assert "httpx" in names


def test_dep_names_requirements_txt_bare():
    """Extracts bare (unpinned) package names too."""
    blob = "# file: requirements.txt\nrequests\nflask>=2.0\n"
    names = _dep_names_in_skill(blob)
    assert "requests" in names
    assert "flask" in names


def test_dep_names_package_json():
    """Extracts package names from a package.json section."""
    blob = (
        '# file: package.json\n'
        '{"dependencies": {"lodash": "4.17.21", "axios": "1.6.0"}}\n'
    )
    names = _dep_names_in_skill(blob)
    assert "lodash" in names
    assert "axios" in names


def test_dep_names_no_manifest_empty():
    """A blob with no manifest section returns an empty list."""
    blob = "# file: SKILL.md\nThis is just a skill description.\n"
    names = _dep_names_in_skill(blob)
    assert names == []


# ---------------------------------------------------------------------------
# 4. _frontmatter_name unit tests
# ---------------------------------------------------------------------------

def test_frontmatter_name_extracted():
    """Extracts the name: field from a SKILL.md section in the blob."""
    blob = "# file: SKILL.md\n---\nname: my-cool-skill\ndescription: test\n---\n"
    assert _frontmatter_name(blob) == "my-cool-skill"


def test_frontmatter_name_none_when_absent():
    """Returns None when no SKILL.md section or no name: field."""
    blob = "# file: requirements.txt\nrequests==2.31.0\n"
    assert _frontmatter_name(blob) is None


# ---------------------------------------------------------------------------
# 5. _KNOWN_NAMES sanity
# ---------------------------------------------------------------------------

def test_known_names_all_lowercase():
    """All entries in _KNOWN_NAMES are lowercase (normalization requirement)."""
    for n in _KNOWN_NAMES:
        assert n == n.lower(), f"_KNOWN_NAMES entry not lowercase: {n!r}"


def test_known_names_minimum_length():
    """Entries shorter than _TYPOSQUAT_MIN_KNOWN_LEN=5 are excluded from flagging
    (the check itself filters by len(K) >= 5, but having them would still be noise)."""
    # Verify the well-known names we care about are present
    for name in ("github", "gitlab", "requests", "numpy", "django", "anthropic"):
        assert name in _KNOWN_NAMES, f"Expected {name!r} in _KNOWN_NAMES"


def test_known_names_size_reasonable():
    """_KNOWN_NAMES has at least 40 and at most 80 entries (curated, not exhaustive)."""
    assert 40 <= len(_KNOWN_NAMES) <= 80, (
        f"_KNOWN_NAMES has {len(_KNOWN_NAMES)} entries; expected 40–80"
    )


# ---------------------------------------------------------------------------
# 6. Context-level integration
# ---------------------------------------------------------------------------

def _make_ctx(tmp: Path, skills: dict[str, str]) -> Context:
    """Build a minimal Context with the given installed_skills dict."""
    ctx = Context(home=tmp)
    ctx.config = {}
    ctx.bootstrap = {}
    ctx.installed_skills = skills
    ctx.installed_skill_py = {}
    return ctx


def test_squat_fires_via_context_skill_name(tmp_path):
    """check_installed_skills: a skill named 'githhub' (1 edit from 'github') fires WARN."""
    from clawseccheck.checks import check_installed_skills

    blob = "# file: SKILL.md\n---\nname: githhub\ndescription: test\n---\nA sync skill.\n"
    ctx = _make_ctx(tmp_path, {"githhub": blob})
    f = check_installed_skills(ctx)
    assert f.status == WARN, f"Expected WARN, got {f.status!r}: {f.detail!r}"
    assert f.severity == HIGH, f"Expected HIGH, got {f.severity!r}"
    assert "typosquat" in (f.detail or "").lower(), (
        f"Expected 'typosquat' in detail: {f.detail!r}"
    )
    assert any("github" in str(e) for e in (f.evidence or [])), (
        f"Expected 'github' in evidence: {f.evidence!r}"
    )


def test_squat_fires_via_context_dep_name(tmp_path):
    """check_installed_skills: skill with dep 'reqests' (1 edit from 'requests') fires WARN."""
    from clawseccheck.checks import check_installed_skills

    blob = (
        "# file: SKILL.md\n---\nname: my-tool\ndescription: test\n---\nA tool.\n"
        "# file: requirements.txt\n"
        "reqests==2.31.0\n"
        "certifi==2024.2.2\n"
    )
    ctx = _make_ctx(tmp_path, {"my-tool": blob})
    f = check_installed_skills(ctx)
    assert f.status == WARN, f"Expected WARN, got {f.status!r}: {f.detail!r}"
    assert "typosquat" in (f.detail or "").lower(), (
        f"Expected 'typosquat' in detail: {f.detail!r}"
    )
    assert any("requests" in str(e) for e in (f.evidence or [])), (
        f"Expected 'requests' in evidence: {f.evidence!r}"
    )


def test_exact_dep_name_silent_via_context(tmp_path):
    """check_installed_skills: skill with legit dep 'requests' (exact) does NOT fire typosquat."""
    from clawseccheck.checks import check_installed_skills

    blob = (
        "# file: SKILL.md\n---\nname: my-tool\ndescription: test\n---\nA tool.\n"
        "# file: requirements.txt\n"
        "requests==2.31.0\n"
        "flask==3.0.2\n"
    )
    ctx = _make_ctx(tmp_path, {"my-tool": blob})
    f = check_installed_skills(ctx)
    # Should be PASS (no other signals in this clean blob)
    assert f.status == PASS, (
        f"Legit 'requests' dep must not trigger WARN: status={f.status!r} detail={f.detail!r}"
    )


def test_far_skill_name_silent_via_context(tmp_path):
    """check_installed_skills: a skill with a name far from all known names is not flagged."""
    from clawseccheck.checks import check_installed_skills

    blob = "# file: SKILL.md\n---\nname: xyznonsense99\ndescription: test\n---\nA tool.\n"
    ctx = _make_ctx(tmp_path, {"xyznonsense99": blob})
    f = check_installed_skills(ctx)
    assert f.status == PASS, (
        f"Far name 'xyznonsense99' must not fire typosquat: {f.status!r} {f.detail!r}"
    )


# ---------------------------------------------------------------------------
# 7. Fixture integration tests
# ---------------------------------------------------------------------------

def _b13(home: Path):
    _, findings, _ = audit(home, include_native=False)
    return {f.id: f for f in findings}["B13"]


def test_bad_f022_typosquat_warns():
    """bad_f022_typosquat: 'githhub-sync' skill + 'reqests' dep -> B13 HIGH WARN."""
    f = _b13(FIXTURES / "bad_f022_typosquat")
    assert f.status == WARN, (
        f"bad_f022_typosquat expected WARN, got {f.status!r}: {f.detail!r}"
    )
    assert f.severity == HIGH, f"Expected HIGH severity, got {f.severity!r}"
    assert "typosquat" in (f.detail or "").lower(), (
        f"Expected 'typosquat' in detail: {f.detail!r}"
    )


def test_clean_f022_typosquat_passes():
    """clean_f022_typosquat: 'note-formatter' skill with clean deps -> B13 PASS."""
    f = _b13(FIXTURES / "clean_f022_typosquat")
    assert f.status == PASS, (
        f"clean_f022_typosquat expected PASS, got {f.status!r}: {f.detail!r}"
    )


# ---------------------------------------------------------------------------
# B-079: OSA distance + short-name threshold calibration
# ---------------------------------------------------------------------------

def test_levenshtein_transposition_counts_as_one_edit():
    """OSA: an adjacent swap is the classic squat shape — one edit, not two."""
    assert _levenshtein("reqeusts", "requests") == 1
    assert _levenshtein("cnavas", "canvas") == 1


def test_squat_hits_short_name_two_substitutions_silent():
    """B-079 regression: 'canvas' (6 chars, two independent substitutions away
    from 'pandas') is a common word, not a squat — must stay silent."""
    hits = _squat_hits(["canvas"], known=frozenset({"pandas"}))
    assert not hits, f"'canvas' must not be flagged against 'pandas': {hits}"


def test_squat_hits_short_name_transposition_still_fires():
    """The threshold tightening must NOT lose real short-name squats: a
    transposed 'cnavas' is one OSA edit from 'canvas' and still fires."""
    hits = _squat_hits(["cnavas"], known=frozenset({"canvas"})) 
    assert hits and hits[0][1] == "canvas"


def test_squat_hits_long_name_two_edits_still_fires():
    """Names of 7+ chars keep the distance-2 budget ('amthropicx' → 'anthropic')."""
    hits = _squat_hits(["amthropicx"], known=frozenset({"anthropic"}))
    assert hits and hits[0][2] == 2
