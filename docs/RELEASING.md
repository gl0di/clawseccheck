# Release protocol (maintainers)

This checklist is for maintainers cutting a release. Users never need it.

## 1) Tests before release

- `python3 -m ruff check .`
- `python3 -m pytest`
- Run the most relevant test subset for the touched area if the full suite is
  too large for your CI window — but a release tag requires the full suite green.

## 2) Documentation and protocol alignment

Update all of the following files (in order), so shipped docs never lag the code:

- `CHANGELOG.md`
- `README.md`
- `SECURITY.md`
- `SECURITY_MODEL.md`
- `SKILL.md`
- `docs/` (regenerate `docs/CHECKS.md` when checks changed)

## 3) Dependabot — review open PRs

- `gh pr list --author app/dependabot` — **review** all open Dependabot PRs
  before tagging. Merge the safe ones; a major-version Action bump may
  deliberately wait — read its release notes first. The point is that no update
  ships un-triaged, not that every update ships immediately.

## 4) Version bump (lock-step)

The version lives in four places and must move together; CI fails the build if
they ever disagree:

1. `clawseccheck/__init__.py` — `__version__`
2. `clawseccheck/__init__.py` — `__released__` (the release date)
3. `SKILL.md` frontmatter `version:` (ClawHub reads this; the publish workflow
   fails if the git tag doesn't equal it)
4. `CHANGELOG.md` — a new top entry

`python3 scripts/bump.py patch|minor|major` writes all four; fill the
CHANGELOG prose by hand.

## 5) Pre-release review gate

- Re-read the release notes and verify that check IDs, remediation text, and
  examples match the implemented code/tests.
- Verify zero false-positive FAILs against real configs — a release must not
  cry wolf.

## 6) Tag and publish

Tag `vX.Y.Z` and push the tag. The publish workflow runs tests again, generates
`SHA256SUMS.txt`, signs it with keyless cosign, creates the GitHub Release with
those assets, and publishes to ClawHub. Publishing is deliberately tag-gated —
there is no auto-release.

## Release-notes template

Lead with user impact; the exhaustive technical changelog can follow below it.

```markdown
## User impact
What changed for normal users, in one or two sentences.

## Added
New checks or capabilities.

## Fixed
False positives, false negatives, and bugs.

## Compatibility
Required OpenClaw/Python versions; breaking changes if any.

## Verification
The release assets include SHA256SUMS.txt and its cosign bundle — see the
README "Is it safe to run?" section for the exact verify command.
```
