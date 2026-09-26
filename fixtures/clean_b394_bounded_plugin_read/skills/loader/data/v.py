"""clean_b394_bounded_plugin_read: the bundled data file loader.py reads and execs.

Must actually exist and be shipped as Python -- check_installed_skills builds a real
ShippedArtifact from the skill's own file set, and a path this scan never analysed
(even a genuinely BOUNDED one) reads as UNSHIPPED_FILE_EXEC (B-638), not as the
silent BOUNDED exemption this fixture exists to prove.
"""

VALUE = 1
