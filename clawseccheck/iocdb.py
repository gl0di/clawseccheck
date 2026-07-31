"""iocdb — dated, provenance-bound indicator-of-compromise dataset.

Layer 1 leaf module (imports nothing from the `clawseccheck` package, per CLAUDE.md
§3) that replaces the inline ``_SOURCE_KNOWN_BAD`` dict formerly hardcoded in
``checks/_vet.py``. Consumed by ``checks/_vet.py`` (``vet_source``'s exact-IOC-match
gate), ``checks/_shared.py``/``checks/_egress.py`` (the C-221 cross-artifact host
correlation), and ``checks/_content.py`` (the install-directive / remote-dependency
known-bad-host checks alongside the existing onion/public-IP heuristics).

GOLDEN RULES BIND HARD HERE (see the workspace CLAUDE.md):

  #1 no network — this dataset ships in-repo as static Python data, refreshed only by
     a deliberate ClawSecCheck release. Nothing in this module ever opens a socket,
     fetches a URL, or reads any "feed" setting. There is no update mechanism here.
  #4 no fabricated IOCs — every record below was independently verified against its
     cited primary-source advisory before it shipped (the same §4/C-145 discipline the
     former inline dict's comments already documented). A record whose provenance
     cannot be traced to a named, checkable advisory does not ship. This module
     ships as a plain ``.py`` (not JSON) deliberately: it sidesteps package-data /
     wheel-inclusion risk entirely (no ``pyproject.toml`` change, no installed-wheel
     test needed) while still making ``REVISION`` a first-class, importable fact.

Each record is a ``dict`` with mandatory provenance fields: ``value``, ``type``,
``first_seen`` (ISO ``YYYY-MM-DD``), ``source_url``, ``source_name``, ``note``.
``validate_dataset()`` mechanically enforces this — a record missing any of these (or
carrying an unparseable/future ``first_seen``) fails ``tests/test_iocdb.py``, which IS
Golden Rule #4's mechanical enforcement, not just documentation of intent.

Freshness is mandatory, not decorative (precedent: ``ledger.freshness_notice`` /
``update.update_notice``). ``REVISION`` is a point-in-time snapshot date; past
``STALE_AFTER_DAYS`` (120 — tighter than ``update.AGE_NUDGE_DAYS``'s 60-day *build*
threshold is loose, but chosen so a dormant dataset is flagged well before the ~140
days it took the piti/openclaw-security-dashboard `ioc/` feed to go silently stale
and start reading as a lying clean — see the 2026-07-29 competitive review),
``freshness_notice()`` returns an explicit "IOC data is N days old" advisory instead
of letting a stale snapshot read as a confident, silent clean. It is wired into
``vet_source()``'s own evidence trail (the one place `_SOURCE_KNOWN_BAD` was
historically consumed) so every IOC-backed verdict from that gate carries it once it
applies; today (dataset only weeks old) it contributes zero lines.
"""
from __future__ import annotations

from datetime import date

REVISION = "2026-07-03"  # dataset point-in-time snapshot date -- bump on every content refresh

# Past this many days since REVISION, freshness_notice() surfaces an explicit
# staleness advisory instead of staying silent. See the module docstring for why
# 120 (not update.py's 60-day build-age threshold, and not ledger.py's 14/30-day
# active-capability thresholds -- this is a slower-moving, release-refreshed dataset).
STALE_AFTER_DAYS = 120

_REQUIRED_FIELDS = ("value", "type", "first_seen", "source_url", "source_name")

# B-384: `type` is not free text -- it doubles as the ecosystem key
# known_bad_sources() pools SOURCES records into (via `pools.setdefault(rec["type"],
# set())`) and as the kind discriminator is_known_bad_host() needs to honor its own
# documented exact-vs-subdomain contract for HOSTS records. Left unpinned, a
# typo'd/mis-cased/space-padded type (e.g. "Clawhub" instead of "clawhub") silently
# minted a brand-new, unreachable-by-ecosystem-lookup pool -- the record still passed
# validate_dataset() (non-empty is all that was checked) while being permanently dead
# via the ecosystem-scoped ("type:name") lookup path (it stayed reachable via
# vet_source's separate "registry" bare-name-iteration branch, which is why this class
# of bug is invisible from one direction and not the other -- see vet_source in
# checks/_vet.py). Pinning the vocabulary here turns that into a validate_dataset()
# failure instead of a silently-dead record.
_SOURCES_TYPE_VOCAB = frozenset({"npm", "pypi", "clawhub", "git", "url", "any"})
_HOSTS_TYPE_VOCAB = frozenset({"ip", "domain"})
_TYPE_VOCAB_BY_LABEL = {"SOURCES": _SOURCES_TYPE_VOCAB, "HOSTS": _HOSTS_TYPE_VOCAB}


def _rec(value: str, type_: str, first_seen: str, source_url: str, source_name: str,
         note: str = "") -> dict:
    return {
        "value": value,
        "type": type_,
        "first_seen": first_seen,
        "source_url": source_url,
        "source_name": source_name,
        "note": note,
    }


# ---------------------------------------------------------------------------------
# sources — known-bad identities per source ecosystem (clawhub / npm / pypi / git).
# `type` doubles as the ecosystem key consumed by known_bad_sources() below.
# Verified verbatim against unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
# (Palo Alto Unit 42, "OpenClaw's Skill Marketplace and the Emerging AI Supply Chain
# Threat", 2026-06-23) -- moved here unchanged from the former checks/_vet.py literal.
# ---------------------------------------------------------------------------------
SOURCES: tuple = (
    _rec(
        "omnicogg", "clawhub", "2026-06-23",
        "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/",
        "Palo Alto Unit 42",
        "AMOS dropper hidden behind ~22 MB README padding (scanner evasion)",
    ),
    _rec(
        "money-radar", "clawhub", "2026-06-23",
        "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/",
        "Palo Alto Unit 42",
        "runtime affiliate-link injection abusing agent advisory authority",
    ),
    _rec(
        "letssendit", "clawhub", "2026-06-23",
        "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/",
        "Palo Alto Unit 42",
        "agentic meme-token front-running scheme",
    ),
    _rec(
        "ai-tradingview-assistant-for-macos", "clawhub", "2026-06-23",
        "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/",
        "Palo Alto Unit 42",
        "macOS infostealer delivery",
    ),
    _rec(
        "tradingview-ai-indicator-assistant", "clawhub", "2026-06-23",
        "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/",
        "Palo Alto Unit 42",
        "macOS infostealer delivery",
    ),
)

# ---------------------------------------------------------------------------------
# publishers — known-bad publisher/author accounts. Empty in v1: the former inline
# dict's comment explicitly excluded the one candidate ("hightower6eu") as unconfirmed
# on its primary source and vet_source has no publisher field to match it against
# anyway (§4 wall) -- carried forward here rather than fabricated to fill the table.
# ---------------------------------------------------------------------------------
PUBLISHERS: tuple = ()

# ---------------------------------------------------------------------------------
# hosts — C2 / drop / exfil hosts and IPs. Consumed by vet_source's url/any pools
# (backward-compatible with the former _SOURCE_KNOWN_BAD["url"] contents), by the
# C-221 cross-artifact correlation (checks/_shared.py / _egress.py), and by the
# install-directive / remote-dependency known-bad-host checks (checks/_content.py).
# ---------------------------------------------------------------------------------
HOSTS: tuple = (
    _rec(
        "91.92.242.30", "ip", "2026-02-01",
        "https://koi.ai/",
        "Koi Security",
        "ClawHavoc C2 -- cross-confirmed by Palo Alto Unit 42 (2026-06-23)",
    ),
    _rec(
        "laosji.net", "domain", "2026-06-23",
        "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/",
        "Palo Alto Unit 42",
        "payload / hosting infrastructure",
    ),
    _rec(
        "letssendit.fun", "domain", "2026-06-23",
        "https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/",
        "Palo Alto Unit 42",
        "letssendit campaign infrastructure",
    ),
)


def all_records() -> tuple:
    """Every record across all three tables, for generic iteration (e.g. by tests)."""
    return SOURCES + PUBLISHERS + HOSTS


def _validate_record(label: str, index: int, rec, *, today: date | None = None) -> list:
    """Validate ONE record; return a list of problem strings (empty = well-formed).

    Factored out of validate_dataset() so the mechanism itself -- Golden Rule #4's
    enforcement -- is directly testable against a synthetic bad record, without ever
    mutating the shipped SOURCES/PUBLISHERS/HOSTS tables. Never raises.
    """
    today = today or date.today()
    problems: list = []
    ident = rec.get("value") if isinstance(rec, dict) else None
    for field in _REQUIRED_FIELDS:
        if not isinstance(rec, dict) or not str(rec.get(field) or "").strip():
            problems.append(f"{label}[{index}] ({ident!r}): missing required field {field!r}")
    # B-384: pin `type` to the vocabulary the label actually consumes.
    # `t not in vocab` (not a `.strip().lower()` comparison) is deliberate -- a
    # mis-cased ("Clawhub") or space-padded (" clawhub") value must fail exactly like
    # a wholly bogus one, never be silently normalized into matching.
    vocab = _TYPE_VOCAB_BY_LABEL.get(label)
    if vocab is not None and isinstance(rec, dict):
        t = rec.get("type")
        if not isinstance(t, str) or t not in vocab:
            problems.append(
                f"{label}[{index}] ({ident!r}): type {t!r} is not in the allowed "
                f"vocabulary {sorted(vocab)!r}"
            )
    fs = rec.get("first_seen") if isinstance(rec, dict) else None
    try:
        parsed = date.fromisoformat(str(fs))
    except (ValueError, TypeError):
        problems.append(f"{label}[{index}] ({ident!r}): first_seen {fs!r} is not ISO YYYY-MM-DD")
    else:
        if parsed > today:
            problems.append(f"{label}[{index}] ({ident!r}): first_seen {fs!r} is in the future")
    return problems


def validate_dataset() -> list:
    """Return a list of problem strings (empty means the dataset is well-formed).

    Mechanically enforces Golden Rule #4: every SHIPPED record must carry a non-empty
    value/type/first_seen/source_url/source_name, and first_seen must parse as an
    ISO YYYY-MM-DD date that is not in the future. Never raises -- callers (the test
    suite) decide what a non-empty result means. Also validates REVISION itself.
    """
    problems: list = []
    today = date.today()
    for label, table in (("SOURCES", SOURCES), ("PUBLISHERS", PUBLISHERS), ("HOSTS", HOSTS)):
        for i, rec in enumerate(table):
            problems.extend(_validate_record(label, i, rec, today=today))
    try:
        rev = date.fromisoformat(str(REVISION))
    except (ValueError, TypeError):
        problems.append(f"REVISION {REVISION!r} is not ISO YYYY-MM-DD")
    else:
        if rev > today:
            problems.append(f"REVISION {REVISION!r} is in the future")
    return problems


def known_bad_sources() -> dict:
    """The `_SOURCE_KNOWN_BAD`-shaped view: {ecosystem: frozenset(lowercased values)}.

    Backward-compatible with the dict `checks/_vet.py` used to hardcode: SOURCES
    records populate their own `type` (ecosystem) pool, and HOSTS records populate
    ONLY the "url" pool -- identical to the former literal, where "any" was an
    explicit, always-empty frozenset(). HOSTS values are meaningful as a URL/git
    source's *host* IOC (matched via vet_source's step 1b host check against the
    "url"/"any" pools), not as a bare package/slug name to be checked against
    EVERY ecosystem via the "any" pool -- putting them there made a pypi/npm/git/
    clawhub package whose bare NAME happens to collide with a host literal
    (e.g. a pypi package literally named "laosji.net") FAIL as a known-bad source,
    even though it has nothing to do with the actual IOC host (a C-135 adversarial
    review caught this widening as a real false positive). Do not re-add HOSTS to
    the "any" pool without re-running that adversarial pass.
    """
    pools: dict = {"npm": set(), "pypi": set(), "clawhub": set(), "git": set(),
                   "url": set(), "any": set()}
    for rec in SOURCES:
        pools.setdefault(rec["type"], set()).add(rec["value"].lower())
    for rec in HOSTS:
        pools["url"].add(rec["value"].lower())
    return {k: frozenset(v) for k, v in pools.items()}


def _build_known_bad_host_records() -> tuple:
    """(value, type) pairs for every HOSTS record, lowercased.

    B-384: is_known_bad_host()'s documented contract is "exact match for
    IP-type records; exact-or-subdomain match for domain-type records" -- honoring that
    requires keeping `type` alongside `value` instead of discarding it (the former
    `known_bad_hosts()`-only lookup applied the domain endswith-subdomain rule
    uniformly to every record regardless of type, so an IP record could wrongly match
    as a "subdomain" of some longer numeric-looking host string).

    Built ONCE at import time -- HOSTS is static in-repo data (see the module
    docstring: no update mechanism, no network), so there is no reason to rebuild this
    on every call. Mirrors checks/_shared.py's `_KNOWN_EXFIL_HOST_RE` "build once at
    import" pattern for the same reason.
    """
    return tuple((rec["value"].lower(), str(rec.get("type") or "").strip().lower()) for rec in HOSTS)


_KNOWN_BAD_HOST_RECORDS: tuple = _build_known_bad_host_records()
_KNOWN_BAD_HOSTS: frozenset = frozenset(v for v, _t in _KNOWN_BAD_HOST_RECORDS)


def known_bad_host_records() -> tuple:
    """(value, type) pairs for every HOSTS record, lowercased -- the same type-aware
    backing structure `is_known_bad_host()` consumes, computed once at import time.

    Exposed (B-384) so a caller building a TEXT-SCANNING regex out of this
    dataset (checks/_shared.py's `_KNOWN_EXFIL_HOST_RE`) can honor the same
    exact-vs-subdomain-by-type contract instead of re-deriving it from the flat,
    type-less `known_bad_hosts()` value set -- which is exactly how two definitions of
    "known-bad host" drifted apart before this fix.
    """
    return _KNOWN_BAD_HOST_RECORDS


def known_bad_hosts() -> frozenset:
    """All HOSTS values (domains + IPs), lowercased.

    Computed once at import time (see `_KNOWN_BAD_HOST_RECORDS` above) -- the same
    frozenset object is returned on every call, never rebuilt (B-384;
    HOSTS is static in-repo data, so a per-call rebuild bought nothing).
    """
    return _KNOWN_BAD_HOSTS


def known_bad_publishers() -> frozenset:
    """All PUBLISHERS values, lowercased."""
    return frozenset(rec["value"].lower() for rec in PUBLISHERS)


def is_known_bad_host(host) -> bool:
    """True when *host* IS, or is a subdomain of, a known-bad host in the dataset.

    Exact match ONLY for "ip"-type records; exact-or-subdomain match for "domain"-type
    records (mirrors vet_source's existing host_l == h or host_l.endswith("." + h)
    check) -- this now actually HONORS the record's own `type` (B-384)
    instead of discarding it and applying the domain subdomain rule to every record
    uniformly. Any type other than "domain" (i.e. "ip", or a defensive fallback for
    anything unexpected) is exact-only: an IP address has no meaningful "subdomain",
    so a longer numeric-looking host string that merely ENDS WITH a known-bad IP's
    digits must never match it that way. Never raises -- a non-string/empty input
    simply returns False.
    """
    h = str(host or "").strip().lower()
    if not h:
        return False
    for bad, typ in _KNOWN_BAD_HOST_RECORDS:
        if h == bad:
            return True
        if typ == "domain" and h.endswith("." + bad):
            return True
    return False


def revision_date() -> date:
    """Parse REVISION to a `date`. Raises ValueError only if the shipped constant
    itself is malformed -- validate_dataset() is what catches that pre-release."""
    return date.fromisoformat(REVISION)


def freshness_notice(*, today: date | None = None) -> list:
    """Advisory-only staleness notice for the IOC dataset (never affects any verdict).

    Returns an empty list when the dataset is within STALE_AFTER_DAYS of REVISION.
    Past the threshold, returns explicit plain-English lines a caller can fold into
    a Finding's evidence (see checks/_vet.py's vet_source) -- mirrors the style of
    `ledger.freshness_notice` / `update.update_notice`. `today` is injectable for
    deterministic tests; `None` uses the real local clock. Never makes a network call.
    """
    today = today or date.today()
    age = max(0, (today - revision_date()).days)
    if age >= STALE_AFTER_DAYS:
        return [
            f"IOC dataset is {age} days old (revision {REVISION}, staleness threshold "
            f"{STALE_AFTER_DAYS} days).",
            "Named-IOC matches (vet_source exact-match, cross-artifact host correlation) "
            "reflect a point-in-time snapshot, not a live feed -- treat a clean/UNKNOWN "
            "result as 'nothing OLD matched', not 'nothing bad exists'. A newer "
            "ClawSecCheck release ships a refreshed snapshot.",
            "(offline notice: based only on this dataset's revision date; no network call "
            "was made)",
        ]
    return []
