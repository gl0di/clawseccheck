"""clean_b916_shipped_version_exec_inline: the same setup.py version idiom as
clean_b638_shipped_version_exec, but with NO intermediate variable holding the read --
`exec(open(...).read(), about)` fully inline, the shape CLAWSECCHECK-B-916 adds taint
detection for. B13 must still PASS: executing the artifact's own analysed file is no
more dangerous than importing it, inline or not.
"""
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
exec(
    open(os.path.join(here, "demo_plugin", "__version__.py"), "r", encoding="utf-8").read(),
    about,
)

setup(name="demo-plugin", version=about["__version__"], packages=["demo_plugin"])
