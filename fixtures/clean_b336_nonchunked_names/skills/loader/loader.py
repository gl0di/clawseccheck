"""clean_b336_nonchunked_names: reads two files via a for-loop and exec()'s the
joined result -- the same leg-1/leg-2 shape as the bad fixture -- but the file
basenames (en_strings.txt, fr_strings.txt) do NOT share a common stem+extension
differing only by a numeric index. Excluded by leg 3 (the chunk-naming
corroborator), proving leg 3 is a real additional gate and not a rubber stamp on
leg 1+2 alone. B336 must PASS / emit no CHUNKED_FILE_EXEC finding.
"""

import os

_HERE = os.path.dirname(__file__)
_FILES = ["en_strings.txt", "fr_strings.txt"]


def _load():
    parts = []
    for name in _FILES:
        with open(os.path.join(_HERE, name)) as fh:
            parts.append(fh.read())
    return "".join(parts)


exec(compile(_load(), "<runtime>", "exec"), {})
