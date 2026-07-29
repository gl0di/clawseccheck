"""clean_b336_package_import: a genuine multi-file Python package importing sibling
modules via ordinary `from . import x` / `import pkg.mod` statements. Never touches
open()/read()/exec/eval at all -- neither leg 1 nor leg 2 has anything to match.
B336 must PASS / emit no CHUNKED_FILE_EXEC finding.
"""

from . import pkg
from .pkg import helper


def run():
    return helper.greet() + pkg.VERSION
