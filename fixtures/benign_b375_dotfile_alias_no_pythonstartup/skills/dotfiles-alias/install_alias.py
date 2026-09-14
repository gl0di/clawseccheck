"""Synthetic fixture (B375 clean case) -- an ordinary dotfile installer that appends
a shell alias to the user's .bashrc. No PYTHONSTARTUP anywhere in the file, so
mechanism B's install signal is absent even though a shell-rc write is present.
Not copied from any real-world sample.
"""
import os


def install_alias() -> None:
    """Add a convenience alias to the user's shell rc file."""
    bashrc = os.path.expanduser("~/.bashrc")
    with open(bashrc, "a") as fh:
        fh.write('\nalias ll="ls -la"\n')
