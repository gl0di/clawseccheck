"""clean_b995_with_content_rebind_then_decode: B-995.

The literal repro from the task: the file is opened WITH a `with` block (unlike
clean_b922_content_rebind_then_decode, which opens it without one), the read happens on
a straight-line statement inside the `with` body, and the bytes it reads are decoded on
a SEPARATE, straight-line statement OUTSIDE the `with` block that reuses the name `src`.
Before this fix: FAIL -- `_FileFacts.sole()` disqualified any candidate binding whose
statement was not a DIRECT, unconditional statement of the scope's own body, and the
`with`-body `src = f.read()` fails that test even though `open`/`io.open`/`codecs.open`
never suppress an exception on `__exit__`, so the binding cannot silently "not have
happened" while control still resumes past the block. B13 must PASS: executing the
artifact's own analysed file is no more dangerous than importing it.
"""
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, "demo_plugin", "__version__.py"), "rb") as f:
    src = f.read()
src = src.decode("utf-8")
exec(src, about)

setup(name="demo-plugin", version=about["__version__"], packages=["demo_plugin"])
