"""Public-doc version-staleness guard.

``v0.21`` / ``v0.23`` feature references survived in README.md deep into the
3.x era because nothing mechanically checked shipped prose for stale version
mentions. This guard scans the shipped public markdown for ``vX.Y``-style
references whose major version is older than the current release's major, so
living docs can't silently describe features in terms of ancient versions
again. Feature history belongs in CHANGELOG.md (excluded by design — history
is its whole point), not in living docs.
"""

from __future__ import annotations

import re
from pathlib import Path

from clawseccheck import __version__

ROOT = Path(__file__).resolve().parent.parent

# Shipped, user-facing markdown that must describe the CURRENT tool.
PUBLIC_DOCS = [
    ROOT / "README.md",
    ROOT / "SKILL.md",
    ROOT / "SECURITY.md",
    ROOT / "SECURITY_MODEL.md",
    ROOT / "CONTRIBUTING.md",
]

# A `v` immediately followed by digits.dot.digits, not preceded by a word/path
# character (so `/download/vX.Y.Z/` template text, `cosign-installer@...v4`,
# and semver-in-URL forms don't false-positive on the letter X placeholder).
_VERSION_REF = re.compile(r"(?<![\w./-])v(\d+)\.(\d+)")

# Deliberate historical mentions:
# {relative path: {exact matched text, ...}} — each entry needs a reason here.
ALLOWLIST: dict = {
    # Historical contract baseline — the frozen-schema doc legitimately dates itself.
    #
    # 4.0.0 widened this on the SAME reasoning the v2.0 entry already stands on, after
    # reading each site rather than sweeping the file: OUTPUT_SCHEMA.md is a CONTRACT
    # document, and every remaining reference tells a consumer of machine output what an
    # OLDER artifact says differently — "through v3.61.0 this block published `configBlind`
    # alone, so a run capped by an open CRITICAL emitted SARIF that said nothing about it",
    # and §17's own "Not part of the public contract" list cites v3.60.0 replacing
    # `inventory.system` as its worked example of a key set that legitimately moved in a
    # minor. Deleting those would remove information a reader of a stored report needs;
    # they are the document's subject, not stale prose about the living tool.
    #
    # What was NOT allowlisted, deliberately: the two `generated_by` EXAMPLE VALUES. An
    # example exists to show the current shape, so a stale one misleads rather than
    # records — those were updated to the release version instead.
    "docs/OUTPUT_SCHEMA.md": {"v2.0", "v3.8", "v3.56", "v3.60", "v3.61"},
    # External OWASP document version ("v1.0 2026"), not a ClawSecCheck version.
    "docs/THREAT_COVERAGE.md": {"v1.0"},
}


def _public_docs():
    docs_dir = ROOT / "docs"
    return PUBLIC_DOCS + sorted(p for p in docs_dir.glob("*.md"))


def test_public_docs_have_no_pre_current_major_version_refs():
    current_major = int(__version__.split(".")[0])
    offenders = []
    for path in _public_docs():
        rel = path.relative_to(ROOT).as_posix()
        allowed = ALLOWLIST.get(rel, set())
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _VERSION_REF.finditer(line):
                if int(m.group(1)) < current_major and m.group(0) not in allowed:
                    offenders.append(f"{rel}:{lineno}: {m.group(0)!r} in: {line.strip()[:100]}")
    assert not offenders, (
        "Stale version references in shipped docs (feature history belongs in "
        "CHANGELOG.md, not living docs):\n" + "\n".join(offenders)
    )
