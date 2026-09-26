"""bad_b922_content_rebind_replaced: CLAWSECCHECK-B-922 mutation check.

The SAME straight-line content-rebind shape as clean_b922_content_rebind_then_decode
(read without `with`, second straight-line statement reuses the name `src`) -- but this
time the second statement REPLACES `src` with attacker-influenced data (an environment
variable) instead of merely decoding the shipped file's own bytes. The value reaching
exec() is no longer the shipped file's content, so B13 must still FAIL: sole()'s
"before=" threading resolves the REACHING (last) binding before the use point, not just
any prior binding, and content() only recognises a resolved value as shipped content
when it is itself a `.decode()` of a shipped read (or another such trusted primitive) --
`os.environ.get(...)` is neither, so this stays caught exactly as before this fix.
"""
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
h = open(os.path.join(here, "demo_plugin", "__version__.py"), "rb")
src = h.read()
h.close()
src = os.environ.get("DEMO_PAYLOAD", "")
exec(src, about)

setup(name="demo-plugin", version=about["__version__"], packages=["demo_plugin"])
