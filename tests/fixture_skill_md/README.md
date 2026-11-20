# Fixture skill manifests

**These are deliberately unsafe test inputs for ClawSecCheck's scanner. Never install them.**

Each `SKILL.md.fixture` here is the `SKILL.md` of a test fixture skill under `fixtures/`, at the
same relative path. Many of them imitate malicious skills on purpose.

They are stored under a different name so that skill catalogs, which index every file named
`SKILL.md` in a public repository, do not list them as installable skills. The test setup
(`tests/_fixtureskills.py`) writes each one back to `fixtures/<path>/SKILL.md` before the suite
runs. Those generated files are gitignored.

To add a fixture skill, create `tests/fixture_skill_md/<fixture>/.../<skill>/SKILL.md.fixture`
and run the tests. Never commit a `SKILL.md` under `fixtures/`.
