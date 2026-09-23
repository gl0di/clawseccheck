"""clean_b638_split_anchor_rebind: the same setup.py version idiom as
clean_b638_shipped_version_exec, but with the path anchor built across two
straight-line statements instead of one nested expression.

exec() runs demo_plugin/__version__.py -- a file this skill ships, whose path resolves
inside the skill directory. B13 must PASS: rebinding `here` twice in unconditional,
same-scope, straight-line code (no branch, no loop, no function boundary) is no
different from computing it in one nested call.
"""
import os

from setuptools import setup

here = os.path.dirname(__file__)
here = os.path.abspath(here)

about = {}
with open(os.path.join(here, "demo_plugin", "__version__.py"), "r", encoding="utf-8") as f:
    exec(f.read(), about)

setup(name="demo-plugin", version=about["__version__"], packages=["demo_plugin"])
