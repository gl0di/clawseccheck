"""clean_b638_shipped_version_exec: the canonical setup.py version idiom.

exec() runs demo_plugin/__version__.py -- a file this skill ships, whose path resolves
inside the skill directory. B13 must PASS: executing the artifact's own analysed file is
no more dangerous than importing it.
"""
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, "demo_plugin", "__version__.py"), "r", encoding="utf-8") as f:
    exec(f.read(), about)

setup(name="demo-plugin", version=about["__version__"], packages=["demo_plugin"])
