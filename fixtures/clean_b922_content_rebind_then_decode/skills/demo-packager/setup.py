"""clean_b922_content_rebind_then_decode: CLAWSECCHECK-B-922.

The same setup.py idiom as clean_b638_shipped_version_exec, but the file is opened
without a `with` block and the bytes it reads are decoded on a SEPARATE, straight-line
statement that reuses the name `src` -- instead of one nested `f.read().decode(...)`
expression. Before this fix: FAIL -- `_FileFacts.sole()`'s "before this use point"
constraint (added for a PATH-anchor variable by CLAWSECCHECK-B-638 round 1) was never
threaded into `content()`'s own Name branch, so a CONTENT variable rebound twice in
unconditional, same-scope, straight-line code lost the proof even though the value
reaching exec() is unambiguously the shipped file's own content. B13 must PASS:
executing the artifact's own analysed file is no more dangerous than importing it.
"""
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")
src = h.read()
h.close()
src = src.decode("utf-8")
exec(src, about)

setup(name="demo-plugin", version=about["__version__"], packages=["demo_plugin"])
