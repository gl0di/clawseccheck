"""Keep pytest out of `fixtures/`.

Fixture trees are INPUT DATA for the audit engine, not part of the suite. Some of them
must contain files whose names follow real test-file conventions (`test_*.py`,
`*_test.sh`, `conftest.py`) — that naming is precisely what the checks under test key
on, e.g. `_pos_in_test_fixture_file` in `clawseccheck/checks/_vet.py`, which suppresses
a finding only when a hit sits inside a file that both looks and reads like a test.

Without this, pytest's default `test_*.py` / `*_test.py` globs collect those files and
the run dies at import: they reference modules that intentionally do not exist, because
they are prose-shaped samples of real skills, not runnable code.

`collect_ignore_glob` is applied to every directory at or below this one.
"""
collect_ignore_glob = ["*"]
