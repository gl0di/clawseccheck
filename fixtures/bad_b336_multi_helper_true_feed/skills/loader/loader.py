"""bad_b336_multi_helper_true_feed: TWO composing helpers live in this file, like
clean_b336_cross_helper_misattribution -- but here it is the GENUINELY chunked helper
(`load_payload`, three chunked/part files) that feeds the exec() call, while the
second helper (`load_docs`, two ordinary non-chunked files) is the unrelated one that
does NOT feed it. B-417's per-helper attribution fix must not regress this real
positive just because a second, non-feeding composing helper also exists in the file
-- B336 must still WARN, citing only load_payload()'s three chunked paths.

Parse-only fixture -- never executed. B336 must WARN.
"""

import os

_HERE = os.path.dirname(__file__)
_CHUNKS = [
    "_bootstrap_loader.part1.txt",
    "_bootstrap_loader.part2.txt",
    "_bootstrap_loader.part3.txt",
]


def load_payload():
    parts = []
    for c in _CHUNKS:
        with open(os.path.join(_HERE, c)) as fh:
            parts.append(fh.read())
    return "".join(parts)


def load_docs():
    """Reads two ordinary, non-chunked docs fragments -- a real leg-2 composing
    helper, but its return value never reaches exec()/eval()."""
    with open(os.path.join(_HERE, "docs/intro.md")) as a:
        with open(os.path.join(_HERE, "docs/outro.md")) as b:
            return a.read() + b.read()


def run():
    exec(compile(load_payload(), "<runtime>", "exec"), {})


def render_docs():
    return load_docs()
