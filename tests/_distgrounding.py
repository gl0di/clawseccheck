"""B-728 — one dist locator with THREE outcomes, because ``skip`` was answering two questions.

Every module that grounds a claim against the installed OpenClaw dist had written its own
locator, and each one collapsed two different states into a single stand-down::

    files = sorted(OPENCLAW_DIST.glob(pattern))
    if not files:
        pytest.skip("installed OpenClaw dist not found")

"OpenClaw is not installed" and "OpenClaw IS installed and this anchor no longer matches"
are different answers, and only the first is a reason to stand down. Bundle filenames are
content-hashed and rotate heavily per release (``docs/CHECK_AUTHORING.md``; 2026.9.1
rotated ~65% of them), so the second is the EXPECTED outcome of an upgrade — which means
that line turned the guard off at exactly the moment it was needed, and printed a false
cause on the way out. A guard able to disable itself and misreport why is worse than no
guard: the run stays green and the reason in the log sends the reader to the wrong place.

Three outcomes, and every caller gets all three:

==============================================  ==========================================
dist directory absent                           ``pytest.skip`` — the one honest stand-down
dist present, zero matches                      FAIL, naming the symbol to re-locate
more than one match where one file is needed    FAIL — picking the first is a coin toss
==============================================  ==========================================

The third is not hypothetical either. ``test_state_schema_grounding.py``'s docstring
records 2026.9.1 moving ``OPENCLAW_STATE_SCHEMA_SQL`` into a different bundle while KEEPING
a file the old glob still matched, so the glob resolved happily to a module that no longer
defined the schema. That module's ``_find_state_schema_defining_js`` is this one's
exemplar, and its lesson is baked in here as ``contains=``: anchoring on a CONSTANT rather
than a filename is strictly stronger, and it also turns a coin toss into a determinate
choice (measured on 2026.9.1: ``agent-id-*.js`` matches four files, exactly one of which
declares ``normalizeAgentIdStrict``).

The second in-tree exemplar is ``test_schema_grounding.py::_require_dist``, whose
anti-vacuity assertion (B-251) is the same idea one level up: a layer that can silently see
nothing must say so rather than grade everything against an empty schema.

WHAT A GREEN GROUNDING TEST MEANS — read this before citing one as evidence. It means the
citation is **live**, not that it is **correct**. These helpers prove a symbol still exists
where a docstring says it does; nothing here can prove the docstring describes what that
symbol actually DOES. A claim about vendor BEHAVIOUR is grounded by EXECUTING the vendor
over a case battery (``test_toolgrant_battery.py``'s per-cell differential against the
pinned vendor answers, ``test_b666_read_reach.py``), never by a successful grep. A locator that resolves is the
precondition for evidence, not the evidence.
"""
from __future__ import annotations

import functools
import os
import re
from pathlib import Path

import pytest

from _realhome import REAL_HOME

#: CLAWSECCHECK-C-583. Test-only: extract a candidate OpenClaw tarball anywhere and point
#: this at its ``dist/`` to ground against it — no fake-``$HOME`` symlink needed. This is
#: the ONLY place that reads it: ``test_schema_grounding.py`` and
#: ``test_state_schema_grounding.py`` both import :data:`OPENCLAW_DIST` below rather than
#: reading the environment themselves, so there is exactly one place a future reader has
#: to check for how the dist path can be steered — and exactly one place `clawseccheck/`
#: would have to import from to stop being test-only, which
#: ``test_the_override_is_test_only_and_unread_by_the_package`` (test_b728_dist_locator.py)
#: asserts it never does.
DIST_OVERRIDE_ENV = "CSC_OPENCLAW_DIST"


def _openclaw_dist_root(env: "dict[str, str] | None" = None) -> Path:
    """:data:`OPENCLAW_DIST`'s value: the real installed dist, or the test-only override.

    ``env`` defaults to the real environment; a test passes a plain ``dict`` so both
    branches are exercised without reloading this module (an env var is read once, at
    import, like ``REAL_HOME`` itself). An override that is SET but empty (an exported,
    blanked shell var) is treated as unset rather than resolving to ``Path("")`` — cwd —
    which would ground against whatever directory happened to be current instead of
    failing loudly or falling back.

    ``REAL_HOME``, never ``Path.home()``, for the fallback — ``conftest`` redirects
    ``$HOME`` for the session, so ``Path.home()`` would find no dist and skip every
    grounding test vacuously (B-519).
    """
    if env is None:
        env = os.environ
    override = env.get(DIST_OVERRIDE_ENV)
    if override:
        return Path(override)
    return REAL_HOME / ".npm-global" / "lib" / "node_modules" / "openclaw" / "dist"


#: When :data:`DIST_OVERRIDE_ENV` is unset, byte-identical to the path this was hard-coded
#: to before CLAWSECCHECK-C-583.
OPENCLAW_DIST = _openclaw_dist_root()


def require_dist() -> Path:
    """The installed dist directory, or the one honest skip.

    Local-only: absent in CI (B-106 — CI checks out only the skill tree) and on any machine
    without OpenClaw. This is the ONLY condition under which a grounding test may stand
    down; every other failure to locate something is a finding, not an excuse.
    """
    if not OPENCLAW_DIST.is_dir():
        pytest.skip(
            f"OpenClaw is not installed at {OPENCLAW_DIST} — dist grounding is local-only"
        )
    return OPENCLAW_DIST


#: The bundle EXTENSION is not part of a citation. OpenClaw 2026.9.3 recompiled the dist
#: chunks from ``.js`` to ``.mjs`` — 8.2, 9.1 and 9.2 all shipped ``.js`` — with no change
#: behind the rename, and that alone blinded 26 grounding tests in one release (B-784).
#: Every caller was wrong in the same way, so the extension is normalised HERE rather than
#: restated in ten call sites: a pattern's trailing spelling names the family, not the file.
#:
#: This is deliberately narrower than re-anchoring the locator on the symbol alone. That is
#: already available as ``contains=`` and is strictly stronger (see the module docstring);
#: what the 9.3 rename showed is that the FILENAME half of the pair must not carry a
#: build-output detail that the vendor flips wholesale.
_JS_EXTS = (".js", ".mjs")


def _spellings(pattern: str) -> "list[str]":
    """``pattern`` under every JS bundle extension, or unchanged if it names none."""
    for ext in _JS_EXTS:
        if pattern.endswith(ext):
            stem = pattern[: -len(ext)]
            return [stem + e for e in _JS_EXTS]
    return [pattern]


def _matches(pattern: str, symbol: str, contains: str | None) -> list:
    dist = require_dist()
    spellings = _spellings(pattern)
    named = sorted({p for spelling in spellings for p in dist.glob(spelling)})
    if contains is None:
        found = named
    else:
        found = [
            p for p in named
            if contains in p.read_text(encoding="utf-8", errors="replace")
        ]
    if found:
        return found

    if contains is not None and named:
        raise AssertionError(
            f"{len(named)} file(s) under {dist} match {pattern!r} "
            f"({', '.join(p.name for p in named)}) but none declares {contains!r}. The "
            f"dist IS installed, so this is a symbol that moved or was renamed, not a "
            f"missing install — re-locate {symbol!r} with "
            f"`grep -rl {symbol!r} {dist}/*` and re-ground this citation."
        )
    raise AssertionError(
        f"nothing under {dist} matches any of {spellings!r}. The dist IS installed, so this "
        f"is a bundle that was renamed (filenames are content-hashed and rotate per "
        f"release), not a missing install — re-locate {symbol!r} with "
        f"`grep -rl {symbol!r} {dist}/*` and re-ground this citation. Standing down "
        f"here would turn the guard off at exactly the moment it is needed."
    )


#: Vendor-sealed helper bundles, which a locator by DECLARATION must skip by name.
#: OpenClaw 2026.9.7 ships ``dist/package-update-activation-recovery.mjs``: 66 MB, unhashed,
#: ``export {}`` only, and no relative import at all. The update path copies it beside the
#: install and runs it under a recovery ``node`` command (``distWorkerPath`` in
#: ``package-update-activation-*.mjs``), so it is a dependency-closure of the whole codebase
#: and re-declares nearly every vendor function. Counted as a declarer it turns every
#: "declared in exactly one bundle" lookup into a coin toss between the real module and a
#: snapshot of it. It is skipped by NAME because a structural filter ("has no relative
#: import") was tried and rejected: the synthetic bundles the unit tests build have none
#: either. ``test_every_sealed_bundle_is_import_free_in_the_installed_dist`` checks each
#: listed name against the real dist, so a second such helper is noticed, not swallowed.
SEALED_BUNDLES = frozenset({"package-update-activation-recovery.mjs"})


@functools.lru_cache(maxsize=None)
def _declaring_bundles(dist: Path, declaration: str) -> "tuple[Path, ...]":
    """Every top-level bundle under ``dist`` with a line STARTING with ``declaration``.

    Bytes and a substring test before the anchored regex: the dist is ~370 MB, and an
    anchored multi-line regex over a 70 MB file is ~25x slower than the substring test that
    rules almost every bundle out."""
    needle = declaration.encode()
    rx = re.compile(b"^" + re.escape(needle), re.M)
    found = []
    for path in sorted({p for ext in _JS_EXTS for p in dist.glob("*" + ext)}):
        if path.name in SEALED_BUNDLES:
            continue
        data = path.read_bytes()
        if needle in data and rx.search(data):
            found.append(path)
    return tuple(found)


def dist_declaring(declaration: str, *, symbol: str) -> Path:
    """The ONE top-level dist bundle that DECLARES ``symbol`` -- located by content, not name.

    ``declaration`` is the literal text a line of that bundle starts with
    (``"function collectConfiguredModelRefs("``). This is the locator for a symbol whose
    host bundle has rotated or been merged away more than once, where a filename glob keeps
    going stale: the declaration line is the shape, the hash and the file are not.
    :data:`SEALED_BUNDLES` are skipped. Zero matches is a finding (the dist IS installed),
    never a skip; two or more is a coin toss and fails the same way :func:`dist_file` does.
    """
    dist = require_dist()
    found = _declaring_bundles(dist, declaration)
    if not found:
        raise AssertionError(
            f"no bundle under {dist} declares {declaration!r} (sealed helpers skipped: "
            f"{sorted(SEALED_BUNDLES)}). The dist IS installed, so {symbol!r} moved, was "
            f"renamed or was inlined -- re-locate it with `grep -rlE '^{declaration}' "
            f"{dist}/*` and re-ground this citation; do not stand down."
        )
    if len(found) != 1:
        raise AssertionError(
            f"{len(found)} bundles under {dist} declare {declaration!r} "
            f"({', '.join(p.name for p in found)}), but this citation for {symbol!r} needs "
            f"exactly one -- taking the first would be a coin toss. If one is a vendor-sealed "
            f"helper, add its name to SEALED_BUNDLES with the evidence."
        )
    return found[0]


def dist_files(pattern: str, *, symbol: str, contains: str | None = None) -> list:
    """Every dist file matching ``pattern`` (and declaring ``contains``, when given).

    At least one, guaranteed: zero is an ``AssertionError`` naming ``symbol``, never a
    skip. Use this where the citation legitimately spans several bundles; use
    :func:`dist_file` where exactly one file must be chosen.
    """
    return _matches(pattern, symbol, contains)


def dist_file(pattern: str, *, symbol: str, contains: str | None = None) -> Path:
    """The ONE dist file this citation names — never ``sorted(...)[0]``.

    More than one match is an ``AssertionError``, because choosing the first is a coin
    toss and the loser is silent. Narrow with ``contains=`` (anchor on the symbol, not the
    filename) rather than trusting sort order.
    """
    found = _matches(pattern, symbol, contains)
    if len(found) != 1:
        raise AssertionError(
            f"{len(found)} files under {OPENCLAW_DIST} match {pattern!r}"
            + (f" and declare {contains!r}" if contains else "")
            + f" ({', '.join(p.name for p in found)}), but this citation for {symbol!r} "
            f"needs exactly one — taking the first would be a coin toss. Narrow it with "
            f"contains=<a constant the right bundle declares>, or split the citation."
        )
    return found[0]


def dist_text(pattern: str, *, symbol: str, contains: str | None = None) -> str:
    """The matching dist files' text, joined. See :func:`dist_files` for the guarantees."""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in _matches(pattern, symbol, contains)
    )


# --------------------------------------------------------------- the tool-catalog records
# C-472 / C-683: ONE parser for ``CORE_TOOL_DEFINITIONS``, shared by every test that grounds
# a tool id against it (B-667, B-674) -- two private copies had already drifted apart once.
#
# A tool record is ``{ id, [executionLocation,] description, sectionId, profiles, ... }`` and
# a CATEGORY record is ``{ id, label }``. OpenClaw 2026.10.1 inserted an ``executionLocation``
# line BETWEEN ``id`` and ``description`` on 14 tool records (``read``, ``write``, ``edit``,
# ``exec``, ``ls``, ``apply_patch``, ``browser``, ``computer``, ``portal``, ``presence``,
# ``process``, ``sessions_send``, ``sessions_spawn``, ``skill_workshop``), so the earlier
# ``id`` / ``description`` / ``sectionId`` ADJACENCY regex stopped seeing those tools. The
# parser therefore reads each record as a unit -- its ``id:`` line up to its closing brace --
# and asks what the record CARRIES, not which line follows which. A record that carries
# neither ``sectionId`` nor ``label`` is returned as neither, and the callers' partition
# assertion (every ``id:`` in the file is a tool or a category) turns that into a red test.
_CATALOG_RECORD_RE = re.compile(
    r'\n\t*\{\n\t*id: "([a-z0-9_]+)",(.*?)\n\t*\},?(?=\n)', re.S)
_CATALOG_SECTION_RE = re.compile(r'\n\t*sectionId: "([a-z0-9_]+)"')


# C-744: OpenClaw 2026.10.5 rewrote ``CORE_TOOL_DEFINITIONS`` from one object literal per tool
# into ``...coreTools("<section>", { <defaults> }, [["<id>", "<description>", { <overrides> }?], ...])``
# calls, with ``sectionId`` and the section's defaults merged in by a function. Every adjacency or
# "record carries sectionId" regex went blind at once (0 tools). ``catalog_tool_records`` reads the
# NEW form structurally -- bracket-aware, string-aware, not a regex over the layout -- and
# returns ``{id: {"sectionId", "profiles"}}`` with the same merge ``coreTools`` does (an
# override replaces the default). It returns ``{}`` for the old form, so callers fall back.

def _js_skip_string(text: str, i: int) -> int:
    """Index just past the string literal opening at *i* (``"``, ``'`` or a backtick)."""
    q = text[i]
    i += 1
    while i < len(text) and text[i] != q:
        i += 2 if text[i] == "\\" else 1
    return i + 1


def _js_split_top(text: str) -> "list[str]":
    """Split *text* on commas that sit at bracket depth 0 (strings stepped over)."""
    parts, depth, start, i = [], 0, 0, 0
    while i < len(text):
        c = text[i]
        if c in "\"'`":
            i = _js_skip_string(text, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _js_matching(text: str, i: int) -> int:
    """Index of the bracket closing the one that opens at *i*."""
    depth = 0
    while i < len(text):
        c = text[i]
        if c in "\"'`":
            i = _js_skip_string(text, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise AssertionError("unbalanced bracket in the tool catalog")


_PROFILES_FIELD_RE = re.compile(r"profiles:\s*\[([^\]]*)\]")


def catalog_tool_records(text: str) -> "dict[str, dict]":
    """``{tool id: {"sectionId": str, "profiles": [str, ...]}}`` for the ``coreTools(...)`` form."""
    head = re.search(r"CORE_TOOL_DEFINITIONS\s*=\s*\[", text)
    if head is None:
        return {}
    end = _js_matching(text, head.end() - 1)
    body = text[head.end():end]
    out: "dict[str, dict]" = {}
    for call in re.finditer(r"\.\.\.coreTools\(", body):
        close = _js_matching(body, call.end() - 1)
        args = _js_split_top(body[call.end():close])
        assert len(args) == 3, f"coreTools call with {len(args)} args -- the builder changed"
        section = args[0].strip("\"'`")
        dm = _PROFILES_FIELD_RE.search(args[1])
        default_profiles = re.findall(r'"([a-z]+)"', dm.group(1)) if dm else []
        assert args[2].startswith("[") and args[2].endswith("]"), "coreTools tools arg moved"
        for entry in _js_split_top(args[2][1:-1]):
            assert entry.startswith("[") and entry.endswith("]"), entry[:60]
            fields = _js_split_top(entry[1:-1])
            if not re.fullmatch(r'"[a-z0-9_]+"', fields[0]):
                # an id spelled as an IMPORTED identifier (`AUTOMATIONS_TOOL_NAME`): the old
                # one-literal-per-tool parser never saw those either (66 tools on 2026.10.4),
                # and resolving it would need the sibling bundle -- left out, as before
                continue
            tool_id = fields[0].strip('"')
            profiles = default_profiles
            if len(fields) > 2:
                om = _PROFILES_FIELD_RE.search(fields[2])
                if om:
                    profiles = re.findall(r'"([a-z]+)"', om.group(1))
            out[tool_id] = {"sectionId": section, "profiles": profiles}
    return out


def catalog_tool_sections(text: str) -> "dict[str, str]":
    """``{tool id: sectionId}`` for the TOOL records -- the ones carrying ``sectionId``.

    No category record carries one (measured on 2026.10.1: 66 tool records, 14 category
    records, none in neither bucket); ``nodes`` and ``sessions`` are each both a tool and a
    category, which is why the discriminator is the field and not the id.
    """
    records = catalog_tool_records(text)
    if records:     # the 2026.10.5 ``coreTools(...)`` form
        return {tool_id: rec["sectionId"] for tool_id, rec in records.items()}
    return {
        m.group(1): s.group(1)
        for m in _CATALOG_RECORD_RE.finditer(text)
        for s in [_CATALOG_SECTION_RE.search(m.group(2))] if s
    }


def catalog_tool_ids(text: str) -> set:
    """Ids of TOOL records (the ones carrying ``sectionId``)."""
    return set(catalog_tool_sections(text))


def catalog_category_ids(text: str) -> set:
    """Ids of CATEGORY records (the ones carrying ``label``)."""
    return {
        m.group(1)
        for m in _CATALOG_RECORD_RE.finditer(text)
        if re.match(r'\n\t*label:', m.group(2))
    }
