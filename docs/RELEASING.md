# Release protocol (maintainers)

This checklist is for maintainers cutting a release. Users never need it.

## 1) Tests before release

- `python3 -m ruff check .`
- `python3 -m pytest`
- Run the most relevant test subset for the touched area if the full suite is
  too large for your CI window — but a release tag requires the full suite green.
- **Run the suite on the supported Python floor too, not only your own interpreter.**
  This is not a formality: a stdlib predicate whose semantics moved between versions
  can change a *verdict* rather than crash. One such change once made two checks
  accept a world-open proxy — the exact lying PASS they exist to prevent.

### The gates that are not in the test suite

A green suite answers "does the code do what its tests say". These answer questions the
suite structurally cannot ask, and a release runs all of them:

| gate | the question only it asks |
| --- | --- |
| `scripts/fleet_fp_gate.py compare` | does this build raise a FAIL on real configs that the last one did not? A new FAIL id/target is a hard blocker until diagnosed. |
| `scripts/monitor_detection_gate.py` | does the watch actually *say so* when something dangerous changes? The FP gate only proves it stays quiet — which a broken detector also does. ~20 minutes. |
| `scripts/dist_citation_gate.py` | do the citations in our source still resolve against the installed OpenClaw? |
| `scripts/state_db_drift_gate.py` | do the queries we issue still match the state DB the runtime ships? Run it after starting the new build, since the DB migrates on first start. |

Note what a green gate does **not** cover: the false-positive gate compares FAIL
findings only, so a false result reached through the attack-chain layer is invisible to
it. Read it as "no new false FAIL", never as "no new false verdict".

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
README "🔒 Safe to run" section for the exact verify command.
```
