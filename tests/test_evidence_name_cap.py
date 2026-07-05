"""B-111: attacker-controlled archive member names are length-capped before they reach
evidence text, so a crafted multi-KB zip/tar entry name cannot bloat the report.

A filesystem path component is OS-bounded (~255 bytes), but an archive member name is not
OS-limited — that is the genuinely-unbounded vector the cap addresses.
"""
from clawseccheck.collector import _UNTRUSTED_NAME_CAP, _cap_name


def test_cap_name_leaves_short_names_unchanged():
    name = "skills/evil/payload.js"
    assert _cap_name(name) == name


def test_cap_name_at_boundary_is_unchanged():
    name = "a" * _UNTRUSTED_NAME_CAP
    assert _cap_name(name) == name


def test_cap_name_bounds_a_multi_kb_member_name():
    hostile = "A" * 8000  # a crafted archive entry name, not OS-length-limited
    out = _cap_name(hostile)
    assert out.startswith("A" * _UNTRUSTED_NAME_CAP)
    assert out.endswith("...(truncated)")
    # bounded: the cap plus the short marker, never the full 8 KB
    assert len(out) <= _UNTRUSTED_NAME_CAP + len("...(truncated)")
    assert len(out) < 200
