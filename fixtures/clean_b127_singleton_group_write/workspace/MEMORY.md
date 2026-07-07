Agent working memory.

Note for maintainers: the test that loads this fixture chmods this file to
0o664 (group-writable) at runtime — permission bits are not portable through
git, so they cannot be committed here. See tests/test_perm_discovery.py
(or test_b20.py) for the B-127 singleton-group-membership assertions that use
this fixture end-to-end via clawseccheck.audit().
