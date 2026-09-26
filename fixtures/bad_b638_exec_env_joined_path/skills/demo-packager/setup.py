"""bad_b638_exec_env_joined_path: the setup.py idiom with one segment taken from the
environment.

os.path.join discards everything before an absolute argument, so DEMO_VERSION_FILE=/tmp/x.py
makes this read and execute a file from anywhere -- the __file__ anchor still sits in the
expression, which is all the older token check looked for. B13 must FAIL.
"""
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, os.environ["DEMO_VERSION_FILE"]), "rb") as fh:
    exec(fh.read().decode("utf-8"), about)

setup(name="demo-plugin", version=about["__version__"], packages=["demo_plugin"])
