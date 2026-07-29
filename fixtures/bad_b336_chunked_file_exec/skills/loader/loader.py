"""bad_b336_chunked_file_exec: assembles a payload by reading and joining three
chunked/part files (_bootstrap_loader.part1.txt, .part2.txt, .part3.txt), then
executes the assembled result with exec() -- the split-by-file scanner-evasion
loader shape (the payload never exists whole in any single shipped .py file).

Parse-only fixture -- never executed. B336 must WARN.
"""

import os

_HERE = os.path.dirname(__file__)
_CHUNKS = [
    "_bootstrap_loader.part1.txt",
    "_bootstrap_loader.part2.txt",
    "_bootstrap_loader.part3.txt",
]


def _load():
    parts = []
    for c in _CHUNKS:
        with open(os.path.join(_HERE, c)) as fh:
            parts.append(fh.read())
    return "".join(parts)


exec(compile(_load(), "<runtime>", "exec"), {})
