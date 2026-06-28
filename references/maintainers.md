# ClawSecCheck — maintainer release protocol

For release branches, keep the workflow explicit and repeatable.

1. Run pre-release checks:
   - `python3 -m ruff check .`
   - `python3 -m pytest`
   - `python3 -m pytest tests/test_cli.py tests/test_cli_flags.py tests/test_attest.py`
   - Focused tests for the area changed in this release.

2. Update all required release documents:
   - `README.md`
   - `CHANGELOG.md`
   - `SECURITY.md`
   - `SECURITY_MODEL.md`
   - `SKILL.md`
   - `SKILL_HE.md`

3. Review: verify that check IDs, risk wording, and remediation guidance in docs match shipped behavior, then create MR/merge and tag flow as agreed by the release process.
